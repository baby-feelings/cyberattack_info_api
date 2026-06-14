"""クローラー（cron.py）のユニットテスト。
実際のネットワークリクエストは httpx のモックで差し替える。
"""
import json
from datetime import date
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.orm import Session

from app.cron import _fetch_cisa_kev, _parse_date, _upsert_vulnerabilities, fetch_and_store_kev
from app.models import Vulnerability

# ── テスト用サンプルデータ ────────────────────────────────────────

SAMPLE_ENTRIES = [
    {
        "cveID": "CVE-2026-99001",
        "vendorProject": "SampleVendor",
        "product": "SampleProduct",
        "vulnerabilityName": "RCE in SampleProduct",
        "shortDescription": "A remote code execution vulnerability.",
        "requiredAction": "Apply the vendor patch immediately.",
        "dateAdded": "2026-06-01",
    },
    {
        "cveID": "CVE-2026-99002",
        "vendorProject": "AnotherCorp",
        "product": "WebServer",
        "vulnerabilityName": "SQL Injection in WebServer",
        "shortDescription": "An SQL injection vulnerability.",
        "requiredAction": None,
        "dateAdded": "2026-06-10",
    },
]

SAMPLE_KEV_RESPONSE = {
    "title": "CISA KEV Catalog",
    "catalogVersion": "2026.06.10",
    "dateReleased": "2026-06-10T00:00:00Z",
    "count": 2,
    "vulnerabilities": SAMPLE_ENTRIES,
}


# ── _parse_date テスト ────────────────────────────────────────────


def test_parse_date_valid():
    """正常な日付文字列をパースできることを確認する。"""
    result = _parse_date("2026-06-14")
    assert result == date(2026, 6, 14)


def test_parse_date_invalid():
    """不正な日付文字列が ValueError を送出することを確認する。"""
    with pytest.raises(ValueError):
        _parse_date("not-a-date")


# ── _fetch_cisa_kev テスト ──────────────────────────────────────


def test_fetch_cisa_kev_success():
    """正常レスポンス時にエントリリストを返すことを確認する。"""
    mock_response = MagicMock()
    mock_response.json.return_value = SAMPLE_KEV_RESPONSE
    mock_response.raise_for_status = MagicMock()

    with patch("app.cron.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.get.return_value = mock_response
        entries = _fetch_cisa_kev()

    assert len(entries) == 2
    assert entries[0]["cveID"] == "CVE-2026-99001"


def test_fetch_cisa_kev_http_error():
    """HTTP エラー時に例外が伝播することを確認する。"""
    import httpx

    mock_response = MagicMock()
    mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
        "404", request=MagicMock(), response=MagicMock()
    )

    with patch("app.cron.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.get.return_value = mock_response
        with pytest.raises(httpx.HTTPStatusError):
            _fetch_cisa_kev()


# ── _upsert_vulnerabilities テスト ──────────────────────────────


def test_upsert_inserts_new_records(db_session: Session):
    """新規エントリが DB に INSERT されることを確認する。"""
    inserted, updated = _upsert_vulnerabilities(db_session, SAMPLE_ENTRIES)

    assert inserted == 2
    assert updated == 0

    record = db_session.query(Vulnerability).filter_by(cve_id="CVE-2026-99001").first()
    assert record is not None
    assert record.vendor_project == "SampleVendor"


def test_upsert_updates_existing_record(db_session: Session):
    """既存エントリの内容変更時に UPDATE されることを確認する。"""
    # 初回 INSERT
    _upsert_vulnerabilities(db_session, [SAMPLE_ENTRIES[0]])

    # 内容を変更して再 Upsert
    modified = {**SAMPLE_ENTRIES[0], "vendorProject": "UpdatedVendor"}
    inserted, updated = _upsert_vulnerabilities(db_session, [modified])

    assert inserted == 0
    assert updated == 1

    record = db_session.query(Vulnerability).filter_by(cve_id="CVE-2026-99001").first()
    assert record.vendor_project == "UpdatedVendor"


def test_upsert_skips_unchanged_record(db_session: Session):
    """内容が変わっていない既存エントリはスキップされることを確認する。"""
    _upsert_vulnerabilities(db_session, [SAMPLE_ENTRIES[0]])

    # 同じ内容で再 Upsert
    inserted, updated = _upsert_vulnerabilities(db_session, [SAMPLE_ENTRIES[0]])

    assert inserted == 0
    assert updated == 0


def test_upsert_skips_entry_without_cve_id(db_session: Session):
    """cveID が空のエントリはスキップされることを確認する。"""
    bad_entry = {**SAMPLE_ENTRIES[0], "cveID": ""}
    inserted, updated = _upsert_vulnerabilities(db_session, [bad_entry])

    assert inserted == 0
    assert updated == 0


# ── fetch_and_store_kev 統合テスト ──────────────────────────────


def test_fetch_and_store_kev_integration():
    """fetch_and_store_kev が正常終了することを確認する（DB・HTTP をモック）。"""
    with (
        patch("app.cron._fetch_cisa_kev", return_value=SAMPLE_ENTRIES),
        patch("app.cron._upsert_vulnerabilities", return_value=(2, 0)),
        patch("app.cron.SessionLocal") as mock_session_cls,
    ):
        mock_db = MagicMock()
        mock_session_cls.return_value = mock_db

        fetch_and_store_kev()  # 例外が発生しないことを確認
