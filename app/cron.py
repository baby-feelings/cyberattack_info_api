"""CISA KEV クローラーモジュール。
米 CISA の Known Exploited Vulnerabilities (KEV) カタログから
脆弱性情報を取得し、DB に Upsert する定期バッチ処理を担う。
"""
import logging
from datetime import date
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.crawler_log import now_utc, write_crawler_log
from app.database import SessionLocal
from app.models import Vulnerability
from app.notifications import notify_crawl_error, notify_new_vulnerabilities

logger = logging.getLogger(__name__)


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


def fetch_and_store_kev() -> tuple[int, int]:
    """CISA KEV フィードを取得し DB に保存するメインエントリポイント。
    APScheduler および /admin/crawl から呼び出される。
    実行結果（成功・失敗・件数・所要時間）は crawler_logs テーブルに記録する。

    Returns:
        (inserted, updated) のタプル
    """
    logger.info("=== CISA KEV crawler started ===")
    started_at = now_utc()
    db: Session = SessionLocal()
    try:
        entries = _fetch_cisa_kev()
        inserted, updated = _upsert_vulnerabilities(db, entries)
        logger.info(
            "=== CISA KEV crawler completed: inserted=%d, updated=%d ===",
            inserted,
            updated,
        )
        # 実行ログを記録
        write_crawler_log(
            crawler_type="KEV",
            status="success",
            started_at=started_at,
            finished_at=now_utc(),
            inserted=inserted,
            updated=updated,
        )
        # 新規 CVE があれば Slack に通知
        notify_new_vulnerabilities(inserted, updated)
        return inserted, updated
    except Exception as exc:
        logger.error("CISA KEV crawler failed: %s", exc, exc_info=True)
        write_crawler_log(
            crawler_type="KEV",
            status="error",
            started_at=started_at,
            finished_at=now_utc(),
            error_message=str(exc),
        )
        notify_crawl_error(str(exc))
        raise
    finally:
        db.close()
