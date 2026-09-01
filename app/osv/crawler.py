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
from app.core.database import SessionLocal
from app.core.notifications import notify_osv_crawl_error, notify_osv_new_vulnerabilities
from app.core.osv_client import (
    BATCH_SIZE,
    extract_fixed_versions,
    fetch_vuln_by_id,
    parse_severity,
    query_packages_batch,
)
from app.crawler_logs.writer import now_utc, write_crawler_log
from app.osv.models import OsvVulnerability
from app.osv.packages import POPULAR_PACKAGES

logger = logging.getLogger(__name__)

# 後方互換: GCS ベースのクローラーと同じエコシステム名リスト
TARGET_ECOSYSTEMS = list(POPULAR_PACKAGES.keys())


def _build_records(
    vuln: dict[str, Any], modified: datetime
) -> list[dict[str, Any]]:
    """OSV エントリを DB レコード辞書のリストに変換する。

    1つの脆弱性が複数パッケージに影響する場合は 1 レコード/パッケージ を生成する。
    """
    severity, cvss_score = parse_severity(vuln)

    # 公開日時をパース（失敗時は modified で代替）
    published_str = vuln.get("published", "")
    try:
        published = datetime.fromisoformat(
            published_str.replace("Z", "+00:00")
        )
    except (ValueError, AttributeError):
        published = modified

    osv_id = vuln.get("id", "")
    aliases = [a for a in (vuln.get("aliases") or []) if a]
    # 参考リンクは最大 5 件に制限
    refs = [r["url"] for r in (vuln.get("references") or []) if r.get("url")][:5]
    summary = (vuln.get("summary") or "").strip()
    details = (vuln.get("details") or None)

    records: list[dict[str, Any]] = []

    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {}) or {}
        pkg_name = (pkg.get("name") or "").strip()
        pkg_eco = (pkg.get("ecosystem") or "").strip()
        if not pkg_name or not pkg_eco:
            continue

        # 影響バージョンは最大 30 件に制限
        affected_versions = (affected.get("versions") or [])[:30]
        fixed_versions = extract_fixed_versions(affected)

        records.append(
            {
                "osv_id": osv_id,
                "ecosystem": pkg_eco,
                "package_name": pkg_name,
                "aliases": aliases,
                "summary": summary,
                "details": details,
                "severity": severity,
                "cvss_score": cvss_score,
                "affected_versions": affected_versions,
                "fixed_versions": fixed_versions,
                "references": refs,
                "published": published,
                "modified": modified,
            }
        )

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
        elif existing.modified != rec["modified"]:
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


def fetch_and_store_osv(days: int | None = None) -> tuple[int, int, int]:
    """OSV クローラーのメインエントリポイント。

    OSV REST API を使い、各エコシステムの主要パッケージに影響する脆弱性を
    取得して DB に保存する。完了後に古いレコードを削除し、Slack に通知する。
    実行結果（成功・失敗・件数・所要時間）は crawler_logs テーブルに記録する。
    APScheduler から毎日呼び出しされる。

    Args:
        days: 取得対象の直近日数（None の場合は settings.OSV_DAYS を使用）

    Returns:
        (inserted, updated, deleted) のタプル
    """
    effective_days = days if days is not None else settings.OSV_DAYS
    logger.info("=== OSV crawler started (API mode, days=%d) ===", effective_days)
    started_at = now_utc()
    cutoff = datetime.now(timezone.utc) - timedelta(days=effective_days)
    total_inserted = 0
    total_updated = 0
    total_deleted = 0

    db: Session = SessionLocal()
    try:
        for ecosystem, packages in POPULAR_PACKAGES.items():
            try:
                # Step 1: パッケージを BATCH_SIZE ずつ分割して {id, modified} を一括取得
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

                # Step 2: cutoff 以降に更新されたものに絞り込む
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

                # Step 3: 直近のものだけ GET /v1/vulns/{id} で完全情報を取得してレコード構築
                records: list[dict[str, Any]] = []
                for osv_id, modified in recent_refs:
                    try:
                        vuln = fetch_vuln_by_id(osv_id)
                        records.extend(_build_records(vuln, modified))
                    except httpx.HTTPError as exc:
                        logger.warning("Failed to fetch %s: %s", osv_id, exc)

                ins, upd = _upsert_osv_records(db, records)
                total_inserted += ins
                total_updated += upd
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

        # Step 4: 保持期間を超えた古いレコードを削除（DB 容量管理）
        try:
            total_deleted = _delete_old_osv_records(db)
        except Exception as exc:
            logger.error("Failed to delete old OSV records: %s", exc, exc_info=True)

    except Exception as exc:
        write_crawler_log(
            crawler_type="OSV",
            status="error",
            started_at=started_at,
            finished_at=now_utc(),
            inserted=total_inserted,
            updated=total_updated,
            deleted=total_deleted,
            error_message=str(exc),
        )
        notify_osv_crawl_error(str(exc))
        raise
    finally:
        db.close()

    logger.info(
        "=== OSV crawler completed: inserted=%d, updated=%d, deleted=%d ===",
        total_inserted, total_updated, total_deleted,
    )
    # 実行ログを記録
    write_crawler_log(
        crawler_type="OSV",
        status="success",
        started_at=started_at,
        finished_at=now_utc(),
        inserted=total_inserted,
        updated=total_updated,
        deleted=total_deleted,
    )
    # 新規・更新があった場合のみ Slack 通知
    notify_osv_new_vulnerabilities(total_inserted, total_updated, total_deleted)
    return total_inserted, total_updated, total_deleted
