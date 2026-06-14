"""API エンドポイントのテスト。
認証・ページネーション・フィルタリング・直近データ取得を検証する。
"""
import pytest
from datetime import date, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import Vulnerability
from tests.conftest import TEST_API_KEY


def _make_vuln(
    db: Session,
    cve_id: str = "CVE-2026-00001",
    vendor: str = "TestVendor",
    product: str = "TestProduct",
    days_ago: int = 5,
) -> Vulnerability:
    """テスト用脆弱性レコードを作成するヘルパー。"""
    vuln = Vulnerability(
        cve_id=cve_id,
        vendor_project=vendor,
        product=product,
        vulnerability_name=f"Test Vuln {cve_id}",
        description="A test vulnerability",
        required_action="Apply patch",
        date_added=date.today() - timedelta(days=days_ago),
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    return vuln


# ── ヘルスチェック ────────────────────────────────────────────────


def test_health_check(client: TestClient):
    """GET /health が 200 を返すことを確認する。"""
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] in ("ok", "degraded")


def test_root(client: TestClient):
    """GET / が API 情報を返すことを確認する。"""
    response = client.get("/")
    assert response.status_code == 200
    assert "Cyberattack Info API" in response.json()["name"]


# ── 認証テスト ───────────────────────────────────────────────────


def test_list_without_api_key_returns_403(client: TestClient):
    """APIキーなしのリクエストが 403 を返すことを確認する。"""
    response = client.get("/api/vulnerabilities")
    assert response.status_code == 403


def test_list_with_wrong_api_key_returns_403(client: TestClient):
    """不正な API キーで 403 が返ることを確認する。"""
    response = client.get(
        "/api/vulnerabilities",
        headers={"X-API-KEY": "wrong-key"},
    )
    assert response.status_code == 403


def test_list_with_valid_api_key_returns_200(client: TestClient, monkeypatch):
    """正しい API キーで 200 が返ることを確認する。"""
    monkeypatch.setattr("app.auth.settings.API_KEY", TEST_API_KEY)
    response = client.get(
        "/api/vulnerabilities",
        headers={"X-API-KEY": TEST_API_KEY},
    )
    assert response.status_code == 200


# ── 一覧取得テスト ────────────────────────────────────────────────


@pytest.mark.usefixtures("setup_test_db")
def test_list_returns_pagination_fields(client: TestClient, db_session: Session, monkeypatch):
    """レスポンスに total/page/per_page/data フィールドが含まれることを確認する。"""
    monkeypatch.setattr("app.auth.settings.API_KEY", TEST_API_KEY)
    _make_vuln(db_session, cve_id="CVE-2026-10001")

    response = client.get(
        "/api/vulnerabilities?page=1&per_page=10",
        headers={"X-API-KEY": TEST_API_KEY},
    )
    assert response.status_code == 200
    body = response.json()
    assert "total" in body
    assert "page" in body
    assert "per_page" in body
    assert "data" in body
    assert isinstance(body["data"], list)


def test_list_search_filter(client: TestClient, db_session: Session, monkeypatch):
    """search パラメータがベンダー・製品名の部分一致フィルタとして機能することを確認する。"""
    monkeypatch.setattr("app.auth.settings.API_KEY", TEST_API_KEY)
    _make_vuln(db_session, cve_id="CVE-2026-10002", vendor="MegaCorp", product="MegaProduct")
    _make_vuln(db_session, cve_id="CVE-2026-10003", vendor="OtherVendor", product="OtherProduct")

    response = client.get(
        "/api/vulnerabilities?search=MegaCorp",
        headers={"X-API-KEY": TEST_API_KEY},
    )
    assert response.status_code == 200
    data = response.json()["data"]
    assert all("MegaCorp" in item["vendor_project"] for item in data)


# ── 直近データ取得テスト ────────────────────────────────────────


def test_recent_returns_list(client: TestClient, db_session: Session, monkeypatch):
    """GET /api/vulnerabilities/recent がリストを返すことを確認する。"""
    monkeypatch.setattr("app.auth.settings.API_KEY", TEST_API_KEY)
    _make_vuln(db_session, cve_id="CVE-2026-20001", days_ago=3)
    _make_vuln(db_session, cve_id="CVE-2026-20002", days_ago=60)  # 範囲外

    response = client.get(
        "/api/vulnerabilities/recent?days=30",
        headers={"X-API-KEY": TEST_API_KEY},
    )
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    # 60日前のデータは含まれないことを確認
    cve_ids = [item["cve_id"] for item in data]
    assert "CVE-2026-20001" in cve_ids
    assert "CVE-2026-20002" not in cve_ids


def test_recent_without_api_key_returns_403(client: TestClient):
    """GET /api/vulnerabilities/recent も認証が必要なことを確認する。"""
    response = client.get("/api/vulnerabilities/recent")
    assert response.status_code == 403
