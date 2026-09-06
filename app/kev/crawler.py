"""CISA KEV クローラーモジュール。
米 CISA の Known Exploited Vulnerabilities (KEV) カタログから
脆弱性情報を取得し、DB に Upsert する定期バッチ処理を担う。
"""
import logging
from datetime import date, timedelta
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.notifications import notify_error, notify_success
from app.crawler_logs.writer import now_utc, write_crawler_log
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
        response = client.get(settings.CISA_KEV_URL)
        response.raise_for_status()

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
            db.add(Vulnerability(**record_data))
            inserted += 1
        else:
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
            response = client.get(_EPSS_API_URL, params={"cve": ",".join(batch)})
            response.raise_for_status()
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


def _delete_old_kev_records(db: Session) -> int:
    """保持期間（KEV_RETENTION_DAYS）を超えた KEV レコードを削除する。

    date_added が cutoff より古いレコードを一括削除して DB 容量を管理する。

    Returns:
        削除件数
    """
    cutoff = date.today() - timedelta(days=settings.KEV_RETENTION_DAYS)
    deleted = (
        db.query(Vulnerability)
        .filter(Vulnerability.date_added < cutoff)
        .delete(synchronize_session=False)
    )
    db.commit()
    logger.info("KEV old records deleted: %d (date_added < %s)", deleted, cutoff)
    return deleted


def fetch_and_store_kev() -> tuple[int, int, int]:
    """CISA KEV フィードを取得し DB に保存するメインエントリポイント。
    APScheduler および /admin/crawl から呼び出される。
    実行結果（成功・失敗・件数・所要時間）は crawler_logs テーブルに記録する。

    Returns:
        (inserted, updated, deleted) のタプル
    """
    logger.info("=== CISA KEV crawler started ===")
    started_at = now_utc()
    db: Session = SessionLocal()
    try:
        entries = _fetch_cisa_kev()
        inserted, updated = _upsert_vulnerabilities(db, entries)

        # EPSS スコアの更新。失敗してもKEVクロール自体は成功扱いとする
        try:
            _apply_epss_scores(db)
        except Exception as exc:
            logger.error("Failed to update EPSS scores: %s", exc, exc_info=True)

        # 保持期間を超えた古いレコードを削除（DB 容量管理）。失敗してもクロール自体は成功扱いとする
        deleted = 0
        try:
            deleted = _delete_old_kev_records(db)
        except Exception as exc:
            logger.error("Failed to delete old KEV records: %s", exc, exc_info=True)

        logger.info(
            "=== CISA KEV crawler completed: inserted=%d, updated=%d, deleted=%d ===",
            inserted, updated, deleted,
        )
        # 実行ログを記録
        write_crawler_log(
            crawler_type="KEV",
            status="success",
            started_at=started_at,
            finished_at=now_utc(),
            inserted=inserted,
            updated=updated,
            deleted=deleted,
        )
        # 新規 CVE があれば Slack に通知
        notify_success("KEV", inserted, updated, deleted)
        return inserted, updated, deleted
    except Exception as exc:
        logger.error("CISA KEV crawler failed: %s", exc, exc_info=True)
        write_crawler_log(
            crawler_type="KEV",
            status="error",
            started_at=started_at,
            finished_at=now_utc(),
            error_message=str(exc),
        )
        notify_error("KEV", str(exc))
        raise
    finally:
        db.close()
