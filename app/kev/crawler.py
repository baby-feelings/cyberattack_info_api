"""CISA KEV クローラーモジュール。
米 CISA の Known Exploited Vulnerabilities (KEV) カタログから
脆弱性情報を取得し、DB に Upsert する定期バッチ処理を担う。
"""
import logging
from datetime import date
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.crawler_runner import CrawlCounters, run_crawler
from app.core.retry import request_with_retry
from app.crawler_logs.writer import now_utc
from app.kev.models import Vulnerability

logger = logging.getLogger(__name__)

# FIRST の EPSS（Exploit Prediction Scoring System）API。認証不要・日次更新
_EPSS_API_URL = "https://api.first.org/data/v1/epss"
# 1リクエストあたりのCVE件数（URL長・応答サイズを抑えるための分割単位）
_EPSS_BATCH_SIZE = 100


def _parse_date(raw: str) -> date:
    """CISA の日付文字列 (YYYY-MM-DD) を date オブジェクトに変換する。"""
    return date.fromisoformat(raw)


def _fetch_cisa_kev() -> list[dict[str, Any]]:
    """CISA KEV JSON フィードを取得し、vulnerabilities 配列を返す。

    Returns:
        CISA KEV の脆弱性エントリリスト

    Raises:
        httpx.HTTPError: ネットワークエラーまたは HTTP エラー時
    """
    logger.info("Fetching CISA KEV feed: %s", settings.CISA_KEV_URL)
    with httpx.Client(timeout=30.0) as client:
        response = request_with_retry(lambda: client.get(settings.CISA_KEV_URL))

    data = response.json()
    entries = data.get("vulnerabilities", [])
    logger.info("Fetched %d entries from CISA KEV feed", len(entries))
    return entries


def _upsert_vulnerabilities(db: Session, entries: list[dict[str, Any]]) -> tuple[int, int]:
    """脆弱性エントリを DB に Upsert する。
    cve_id をキーに、新規レコードは INSERT、既存は UPDATE する。

    Args:
        db: SQLAlchemy セッション
        entries: CISA KEV エントリのリスト

    Returns:
        (inserted_count, updated_count) のタプル
    """
    inserted = 0
    updated = 0
    now = now_utc()

    for entry in entries:
        cve_id = entry.get("cveID", "")
        if not cve_id:
            continue  # cveID が無いエントリはスキップ

        # DBから既存レコードを取得
        existing = db.query(Vulnerability).filter(Vulnerability.cve_id == cve_id).first()

        record_data = {
            "cve_id": cve_id,
            "vendor_project": entry.get("vendorProject", ""),
            "product": entry.get("product", ""),
            "vulnerability_name": entry.get("vulnerabilityName", ""),
            "description": entry.get("shortDescription", ""),
            "required_action": entry.get("requiredAction") or None,
            "date_added": _parse_date(entry["dateAdded"]),
        }

        if existing is None:
            # 新規 INSERT
            db.add(Vulnerability(**record_data, fetched_at=now))
            inserted += 1
        else:
            # fetched_at は内容の変更有無に関わらず、今回のクロールで存在確認できた事実
            # として常に更新する（updated_at は内容変更時のみ更新される鮮度指標のため使い分け）
            existing.fetched_at = now
            # 内容に変更があれば UPDATE
            changed = any(
                getattr(existing, key) != value
                for key, value in record_data.items()
                if key != "cve_id"
            )
            if changed:
                for key, value in record_data.items():
                    setattr(existing, key, value)
                updated += 1

    db.commit()
    return inserted, updated


def _fetch_epss_scores(cve_ids: list[str]) -> dict[str, tuple[float, float]]:
    """FIRST EPSS API から指定 CVE 群のスコア・パーセンタイルを取得する。

    Args:
        cve_ids: 問い合わせ対象の CVE ID リスト

    Returns:
        {cve_id: (epss_score, epss_percentile)} の辞書（該当なしの CVE は含まれない）

    Raises:
        httpx.HTTPError: ネットワークエラーまたは HTTP エラー時
    """
    scores: dict[str, tuple[float, float]] = {}
    with httpx.Client(timeout=30.0) as client:
        for i in range(0, len(cve_ids), _EPSS_BATCH_SIZE):
            batch = cve_ids[i : i + _EPSS_BATCH_SIZE]

            def _get_epss_batch(b: list[str] = batch) -> httpx.Response:
                return client.get(_EPSS_API_URL, params={"cve": ",".join(b)})

            response = request_with_retry(_get_epss_batch)
            for item in response.json().get("data", []):
                cve = item.get("cve")
                if not cve:
                    continue
                try:
                    scores[cve] = (float(item["epss"]), float(item["percentile"]))
                except (KeyError, TypeError, ValueError):
                    logger.warning("Skipping malformed EPSS entry for %s: %r", cve, item)
    return scores


def _apply_epss_scores(db: Session) -> int:
    """DB内の全 KEV レコードに EPSS スコアを付与する（日次更新）。

    EPSS スコアは悪用確率の予測モデルであり、CVE の内容自体が変わらなくても
    日次で更新されるため、KEV クロールのたびに全件へ再取得・上書きする。

    Returns:
        スコアを更新した件数
    """
    vulnerabilities = db.query(Vulnerability).all()
    if not vulnerabilities:
        return 0

    scores = _fetch_epss_scores([v.cve_id for v in vulnerabilities])
    now = now_utc()
    updated = 0
    for vuln in vulnerabilities:
        hit = scores.get(vuln.cve_id)
        if hit is None:
            continue
        vuln.epss_score, vuln.epss_percentile = hit
        vuln.epss_updated_at = now
        updated += 1

    db.commit()
    logger.info("EPSS scores updated: %d/%d KEV records", updated, len(vulnerabilities))
    return updated


def _delete_stale_kev_records(db: Session, current_cve_ids: set[str]) -> int:
    """CISA KEV フィードに現在含まれなくなったレコードを削除する。

    以前は `date_added` が `KEV_RETENTION_DAYS`（180日）より古いレコードを削除する
    age-based 実装だったが、これは重大なバグだった。CISA KEV は基本的に追加専用の
    恒久的なカタログで、`date_added`（カタログに追加された日）はエントリが古くなっても
    削除される理由にならない。しかし `_fetch_cisa_kev` は毎回カタログ全件（2021年以降の
    全履歴、時間フィルタなし）を再取得するため、age-based 削除は「毎晩180日超のエントリを
    大量削除 → 翌日の全件再取得で `_upsert_vulnerabilities` がそのまま新規INSERTとして
    復活」という無限ループを引き起こしていた。本番では実際にこれが発生し、180日を超える
    KEV履歴（2021〜2026年前半の大半）が失われていた（Issue #239の調査中に発見）。

    正しい削除条件は「CISAが実際にカタログから取り下げた（今回のフィードに含まれない）」
    ことであり、`date_added` の新旧ではなく `current_cve_ids`（今回のフェッチで実在確認
    できた cve_id 集合）に含まれるかどうかで判定する。

    Args:
        current_cve_ids: 今回のクロールで CISA フィードに実在した cve_id の集合

    Returns:
        削除件数
    """
    if not current_cve_ids:
        # フィード取得自体が空リストを返すのは CISA 側 API 障害等の異常系の可能性が高く、
        # それを理由に全件削除してしまう事故を避ける（フェッチ失敗時は例外で detect される
        # ため、ここに来るのは「取得は成功したが空だった」ケースのみ）
        logger.warning("KEV: current_cve_ids is empty, skipping stale record deletion")
        return 0
    deleted = (
        db.query(Vulnerability)
        .filter(Vulnerability.cve_id.notin_(current_cve_ids))
        .delete(synchronize_session=False)
    )
    db.commit()
    logger.info("KEV stale records deleted: %d (not in current CISA feed)", deleted)
    return deleted


def fetch_and_store_kev(*, force: bool = False) -> tuple[int, int, int]:
    """CISA KEV フィードを取得し DB に保存するメインエントリポイント。
    APScheduler および /admin/crawl から呼び出される。
    実行結果（成功・失敗・件数・所要時間）は crawler_logs テーブルに記録する。

    Args:
        force: True の場合、今日すでに成功実行済みでも強制的に再実行する（Issue #239）

    Returns:
        (inserted, updated, deleted) のタプル
    """
    logger.info("=== CISA KEV crawler started ===")

    def _body(db: Session, counters: CrawlCounters) -> None:
        entries = _fetch_cisa_kev()
        counters.inserted, counters.updated = _upsert_vulnerabilities(db, entries)
        current_cve_ids = {e["cveID"] for e in entries if e.get("cveID")}

        # EPSS スコアの更新。失敗してもKEVクロール自体は成功扱いとする
        try:
            _apply_epss_scores(db)
        except Exception as exc:
            logger.error("Failed to update EPSS scores: %s", exc, exc_info=True)

        # CISAフィードから取り下げられたレコードを削除。失敗してもクロール自体は成功扱いとする
        try:
            counters.deleted = _delete_stale_kev_records(db, current_cve_ids)
        except Exception as exc:
            logger.error("Failed to delete stale KEV records: %s", exc, exc_info=True)

    return run_crawler("KEV", _body, force=force)
