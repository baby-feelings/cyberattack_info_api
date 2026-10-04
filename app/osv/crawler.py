"""OSV (Open Source Vulnerabilities) クローラーモジュール。

OSV REST API (https://api.osv.dev/v1/) を使い、各エコシステムの主要パッケージに
影響する脆弱性を取得して DB に Upsert する。
APScheduler から毎日呼び出される。
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.crawler_runner import CrawlCounters, run_crawler
from app.core.osv_client import (
    BATCH_SIZE,
    extract_fixed_versions,
    fetch_vuln_by_id,
    parse_severity,
    query_packages_batch,
)
from app.crawler_logs.writer import now_utc
from app.osv.models import OsvVulnerability
from app.osv.packages import POPULAR_PACKAGES

logger = logging.getLogger(__name__)

# 後方互換: GCS ベースのクローラーと同じエコシステム名リスト
TARGET_ECOSYSTEMS = list(POPULAR_PACKAGES.keys())


def _parse_osv_datetime(value: Any) -> datetime | None:
    """OSV の ISO8601 日時文字列（末尾 `Z` 可）をパースする。未設定・不正な値は None。"""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _vuln_common_fields(vuln: dict[str, Any], modified: datetime) -> dict[str, Any]:
    """OSV エントリのうち、影響するパッケージによらず共通のレコード項目を組み立てる。"""
    severity, cvss_score = parse_severity(vuln)
    return {
        "osv_id": vuln.get("id", ""),
        "aliases": [a for a in (vuln.get("aliases") or []) if a],
        "summary": (vuln.get("summary") or "").strip(),
        "details": (vuln.get("details") or None),
        "severity": severity,
        "cvss_score": cvss_score,
        # 参考リンクは最大 5 件に制限
        "references": [r["url"] for r in (vuln.get("references") or []) if r.get("url")][:5],
        # 公開日時をパース（失敗時は modified で代替）
        "published": _parse_osv_datetime(vuln.get("published")) or modified,
        "modified": modified,
        # OSVスキーマの withdrawn フィールド。設定されていればソース側で撤回済みのエントリ
        "withdrawn_at": _parse_osv_datetime(vuln.get("withdrawn")),
        "fetched_at": now_utc(),
    }


def _build_records(
    vuln: dict[str, Any], modified: datetime
) -> list[dict[str, Any]]:
    """OSV エントリを DB レコード辞書のリストに変換する。

    1つの脆弱性が複数パッケージに影響する場合は 1 レコード/パッケージ を生成する。
    """
    common = _vuln_common_fields(vuln, modified)
    records: list[dict[str, Any]] = []

    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {}) or {}
        pkg_name = (pkg.get("name") or "").strip()
        pkg_eco = (pkg.get("ecosystem") or "").strip()
        if not pkg_name or not pkg_eco:
            continue

        records.append({
            **common,
            "ecosystem": pkg_eco,
            "package_name": pkg_name,
            # 影響バージョンは最大 30 件に制限
            "affected_versions": (affected.get("versions") or [])[:30],
            "fixed_versions": extract_fixed_versions(affected),
        })

    return records


_COMMIT_EVERY = 50  # 何件ごとにコミットするか（長時間トランザクション回避）


def _delete_old_osv_records(db: Session) -> int:
    """保持期間（OSV_RETENTION_DAYS）を超えた OSV レコードを削除する。

    modified が cutoff より古いレコードを一括削除して DB 容量を管理する。

    Returns:
        削除件数
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.OSV_RETENTION_DAYS)
    deleted = (
        db.query(OsvVulnerability)
        .filter(OsvVulnerability.modified < cutoff)
        .delete(synchronize_session=False)
    )
    db.commit()
    logger.info("OSV old records deleted: %d (modified < %s)", deleted, cutoff.date())
    return deleted


def _upsert_osv_records(
    db: Session, records: list[dict[str, Any]]
) -> tuple[int, int]:
    """OSV レコードを DB に Upsert する。

    (osv_id, ecosystem, package_name) をキーに INSERT または UPDATE する。
    modified が変化していない場合は UPDATE をスキップしてパフォーマンスを最適化する。
    _COMMIT_EVERY 件ごとにコミットして長時間トランザクションを回避する。

    Returns:
        (inserted_count, updated_count) のタプル
    """
    inserted = 0
    updated = 0

    # レコードリスト内の重複 (osv_id, ecosystem, package_name) を除去
    seen_keys: set[tuple[str, str, str]] = set()
    unique_records: list[dict[str, Any]] = []
    for rec in records:
        key = (rec["osv_id"], rec["ecosystem"], rec["package_name"])
        if key not in seen_keys:
            seen_keys.add(key)
            unique_records.append(rec)

    for i, rec in enumerate(unique_records):
        existing = (
            db.query(OsvVulnerability)
            .filter(
                OsvVulnerability.osv_id == rec["osv_id"],
                OsvVulnerability.ecosystem == rec["ecosystem"],
                OsvVulnerability.package_name == rec["package_name"],
            )
            .first()
        )

        if existing is None:
            db.add(OsvVulnerability(**rec))
            inserted += 1
        else:
            # fetched_at は内容の変更有無に関わらず、今回のクロールで存在確認できた事実
            # として常に更新する（updated_at は内容変更時のみ更新される鮮度指標のため使い分け）
            existing.fetched_at = rec["fetched_at"]
            if existing.modified != rec["modified"]:
                # modified が更新されている場合のみ上書き
                for field, value in rec.items():
                    setattr(existing, field, value)
                updated += 1

        # 定期コミットで接続タイムアウトを防ぐ
        if (i + 1) % _COMMIT_EVERY == 0:
            try:
                db.commit()
            except Exception:
                db.rollback()
                raise

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise
    return inserted, updated


def _process_ecosystem(
    db: Session,
    counters: CrawlCounters,
    ecosystem: str,
    packages: list[str],
    cutoff: datetime,
) -> None:
    """1エコシステム分の OSV 取得・DB Upsert を行う（fetch_and_store_osv から呼ばれる）。

    Step 1: パッケージを BATCH_SIZE ずつ分割して {id, modified} を一括取得
    Step 2: cutoff 以降に更新されたものに絞り込む
    Step 3: 直近のものだけ GET /v1/vulns/{id} で完全情報を取得してレコード構築・Upsert

    HTTPError・予期しない例外はこのエコシステム単位で握りつぶし、他エコシステムの
    処理を継続させる（呼び出し元 fetch_and_store_osv の既存挙動を維持）。
    """
    try:
        pkg_tuples = [(pkg, ecosystem) for pkg in packages]
        raw_refs: list[dict[str, Any]] = []
        for i in range(0, len(pkg_tuples), BATCH_SIZE):
            chunk = pkg_tuples[i: i + BATCH_SIZE]
            raw_refs.extend(query_packages_batch(chunk))

        # 複数バッチにまたがる重複 ID を除去
        seen_ids: set[str] = set()
        refs: list[dict[str, Any]] = []
        for ref in raw_refs:
            if ref["id"] not in seen_ids:
                seen_ids.add(ref["id"])
                refs.append(ref)

        # cutoff 以降に更新されたものに絞り込む
        recent_refs = []
        for ref in refs:
            try:
                modified = datetime.fromisoformat(
                    ref["modified"].replace("Z", "+00:00")
                )
                if modified >= cutoff:
                    recent_refs.append((ref["id"], modified))
            except (ValueError, AttributeError, KeyError):
                continue

        logger.info(
            "OSV API [%s]: %d total vulns, %d recent (>= %s)",
            ecosystem, len(refs), len(recent_refs), cutoff.date(),
        )

        # 直近のものだけ GET /v1/vulns/{id} で完全情報を取得してレコード構築
        records: list[dict[str, Any]] = []
        for osv_id, modified in recent_refs:
            try:
                vuln = fetch_vuln_by_id(osv_id)
                records.extend(_build_records(vuln, modified))
            except httpx.HTTPError as exc:
                logger.warning("Failed to fetch %s: %s", osv_id, exc)

        ins, upd = _upsert_osv_records(db, records)
        counters.inserted += ins
        counters.updated += upd
        logger.info(
            "OSV [%s] done: recent=%d records=%d inserted=%d updated=%d",
            ecosystem, len(recent_refs), len(records), ins, upd,
        )

    except httpx.HTTPError as exc:
        logger.error("HTTP error for ecosystem %s: %s", ecosystem, exc)
    except Exception as exc:
        logger.error(
            "Unexpected error for ecosystem %s: %s",
            ecosystem, exc, exc_info=True,
        )


def fetch_and_store_osv(days: int | None = None, *, force: bool = False) -> tuple[int, int, int]:
    """OSV クローラーのメインエントリポイント。

    OSV REST API を使い、各エコシステムの主要パッケージに影響する脆弱性を
    取得して DB に保存する。完了後に古いレコードを削除し、Slack に通知する。
    実行結果（成功・失敗・件数・所要時間）は crawler_logs テーブルに記録する。
    APScheduler から毎日呼び出しされる。

    Args:
        days: 取得対象の直近日数（None の場合は settings.OSV_DAYS を使用）
        force: True の場合、今日すでに成功実行済みでも強制的に再実行する（Issue #239）

    Returns:
        (inserted, updated, deleted) のタプル
    """
    effective_days = days if days is not None else settings.OSV_DAYS
    logger.info("=== OSV crawler started (API mode, days=%d) ===", effective_days)
    cutoff = datetime.now(timezone.utc) - timedelta(days=effective_days)

    def _body(db: Session, counters: CrawlCounters) -> None:
        for ecosystem, packages in POPULAR_PACKAGES.items():
            _process_ecosystem(db, counters, ecosystem, packages, cutoff)

        # 保持期間を超えた古いレコードを削除（DB 容量管理）
        try:
            counters.deleted = _delete_old_osv_records(db)
        except Exception as exc:
            logger.error("Failed to delete old OSV records: %s", exc, exc_info=True)

    return run_crawler("OSV", _body, force=force)
