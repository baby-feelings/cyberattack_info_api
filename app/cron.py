"""CISA KEV クローラーモジュール。
米 CISA の Known Exploited Vulnerabilities (KEV) カタログから
脆弱性情報を取得し、DB に Upsert する定期バッチ処理を担う。
"""
import logging
from datetime import date
from typing import Any

import httpx
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.models import Vulnerability

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


def fetch_and_store_kev() -> None:
    """CISA KEV フィードを取得し DB に保存するメインエントリポイント。
    APScheduler から定期呼び出しされる。
    エラーは握りつぶさず、ログに記録して上位に伝播させる。
    """
    logger.info("=== CISA KEV crawler started ===")
    db: Session = SessionLocal()
    try:
        entries = _fetch_cisa_kev()
        inserted, updated = _upsert_vulnerabilities(db, entries)
        logger.info(
            "=== CISA KEV crawler completed: inserted=%d, updated=%d ===",
            inserted,
            updated,
        )
    except httpx.HTTPError as exc:
        logger.error("HTTP error during CISA KEV fetch: %s", exc)
        raise
    except Exception as exc:
        logger.error("Unexpected error during CISA KEV fetch: %s", exc, exc_info=True)
        raise
    finally:
        db.close()
