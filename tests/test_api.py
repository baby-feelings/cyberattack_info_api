"""API エンドポイントのテスト。
認証・ページネーション・フィルタリング・直近データ取得を検証する。
"""
from datetime import date, timedelta
from unittest.mock import patch

import pytest
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


def test_health_check_db_ok(client: TestClient):
    """GET /health の db_connected フィールドが True であることを確認する。"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["db_connected"] is True


def test_health_check_db_error(client: TestClient):
    """DB 接続失敗時に GET /health が degraded ステータスを返すことを確認する。"""
    from unittest.mock import MagicMock, patch

    # db.execute が例外を送出するジェネレータをモックとして注入
    def failing_get_db():
        mock_db = MagicMock()
        mock_db.execute.side_effect = Exception("DB connection failed")
        yield mock_db

    with patch("app.main.get_db", side_effect=failing_get_db):
        response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["db_connected"] is False


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


def test_list_vendor_filter(client: TestClient, db_session: Session, monkeypatch):
    """vendor パラメータによる完全一致フィルタが機能することを確認する。"""
    monkeypatch.setattr("app.auth.settings.API_KEY", TEST_API_KEY)
    _make_vuln(db_session, cve_id="CVE-2026-10004", vendor="AlphaVendor", product="ProductA")
    _make_vuln(db_session, cve_id="CVE-2026-10005", vendor="BetaVendor", product="ProductB")

    response = client.get(
        "/api/vulnerabilities?vendor=AlphaVendor",
        headers={"X-API-KEY": TEST_API_KEY},
    )
    assert response.status_code == 200
    data = response.json()["data"]
    assert len(data) == 1
    assert data[0]["vendor_project"] == "AlphaVendor"


def test_list_product_filter(client: TestClient, db_session: Session, monkeypatch):
    """product パラメータによる部分一致フィルタが機能することを確認する。"""
    monkeypatch.setattr("app.auth.settings.API_KEY", TEST_API_KEY)
    _make_vuln(db_session, cve_id="CVE-2026-10006", vendor="VendorX", product="SpecialGateway")
    _make_vuln(db_session, cve_id="CVE-2026-10007", vendor="VendorY", product="CommonApp")

    response = client.get(
        "/api/vulnerabilities?product=Gateway",
        headers={"X-API-KEY": TEST_API_KEY},
    )
    assert response.status_code == 200
    data = response.json()["data"]
    assert len(data) == 1
    assert "Gateway" in data[0]["product"]


def test_list_pagination(client: TestClient, db_session: Session, monkeypatch):
    """ページネーションが正しく機能することを確認する。"""
    monkeypatch.setattr("app.auth.settings.API_KEY", TEST_API_KEY)
    for i in range(5):
        _make_vuln(db_session, cve_id=f"CVE-2026-5000{i}", vendor="PagingVendor")

    response = client.get(
        "/api/vulnerabilities?page=1&per_page=2",
        headers={"X-API-KEY": TEST_API_KEY},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 5
    assert len(body["data"]) == 2
    assert body["per_page"] == 2


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


def test_recent_default_days(client: TestClient, db_session: Session, monkeypatch):
    """days パラメータ未指定時はデフォルト 30 日が使われることを確認する。"""
    monkeypatch.setattr("app.auth.settings.API_KEY", TEST_API_KEY)
    _make_vuln(db_session, cve_id="CVE-2026-30001", days_ago=10)

    response = client.get(
        "/api/vulnerabilities/recent",
        headers={"X-API-KEY": TEST_API_KEY},
    )
    assert response.status_code == 200
    cve_ids = [item["cve_id"] for item in response.json()]
    assert "CVE-2026-30001" in cve_ids


# ── CVE 個別取得テスト ────────────────────────────────────────────


def test_get_vulnerability_by_cve_id(client: TestClient, db_session: Session, monkeypatch):
    """GET /api/vulnerabilities/{cve_id} が正しいレコードを返すことを確認する。"""
    monkeypatch.setattr("app.auth.settings.API_KEY", TEST_API_KEY)
    _make_vuln(db_session, cve_id="CVE-2026-40001", vendor="SingleVendor", product="SingleProduct")

    response = client.get(
        "/api/vulnerabilities/CVE-2026-40001",
        headers={"X-API-KEY": TEST_API_KEY},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["cve_id"] == "CVE-2026-40001"
    assert data["vendor_project"] == "SingleVendor"


def test_get_vulnerability_case_insensitive(client: TestClient, db_session: Session, monkeypatch):
    """CVE ID の大文字・小文字を問わず一致することを確認する。"""
    monkeypatch.setattr("app.auth.settings.API_KEY", TEST_API_KEY)
    _make_vuln(db_session, cve_id="CVE-2026-40002")

    response = client.get(
        "/api/vulnerabilities/cve-2026-40002",
        headers={"X-API-KEY": TEST_API_KEY},
    )
    assert response.status_code == 200
    assert response.json()["cve_id"] == "CVE-2026-40002"


def test_get_vulnerability_not_found(client: TestClient, monkeypatch):
    """存在しない CVE ID に対して 404 を返すことを確認する。"""
    monkeypatch.setattr("app.auth.settings.API_KEY", TEST_API_KEY)

    response = client.get(
        "/api/vulnerabilities/CVE-9999-99999",
        headers={"X-API-KEY": TEST_API_KEY},
    )
    assert response.status_code == 404


def test_get_vulnerability_requires_auth(client: TestClient):
    """認証なしでは 403 を返すことを確認する。"""
    response = client.get("/api/vulnerabilities/CVE-2026-00001")
    assert response.status_code == 403


# ── 統計エンドポイントテスト ─────────────────────────────────────


def test_stats_returns_correct_structure(client: TestClient, db_session: Session, monkeypatch):
    """GET /api/vulnerabilities/stats が正しい構造を返すことを確認する。"""
    monkeypatch.setattr("app.auth.settings.API_KEY", TEST_API_KEY)
    _make_vuln(db_session, cve_id="CVE-2026-50001", vendor="VendorA")
    _make_vuln(db_session, cve_id="CVE-2026-50002", vendor="VendorA")
    _make_vuln(db_session, cve_id="CVE-2026-50003", vendor="VendorB")

    response = client.get(
        "/api/vulnerabilities/stats",
        headers={"X-API-KEY": TEST_API_KEY},
    )
    assert response.status_code == 200
    data = response.json()
    assert "total_vulnerabilities" in data
    assert "top_vendors" in data
    assert "monthly_trend" in data
    assert data["total_vulnerabilities"] == 3


def test_stats_top_vendors_sorted(client: TestClient, db_session: Session, monkeypatch):
    """top_vendors が件数の多い順に並んでいることを確認する。"""
    monkeypatch.setattr("app.auth.settings.API_KEY", TEST_API_KEY)
    for i in range(3):
        _make_vuln(db_session, cve_id=f"CVE-2026-6000{i}", vendor="BigVendor")
    _make_vuln(db_session, cve_id="CVE-2026-60099", vendor="SmallVendor")

    response = client.get(
        "/api/vulnerabilities/stats",
        headers={"X-API-KEY": TEST_API_KEY},
    )
    assert response.status_code == 200
    vendors = response.json()["top_vendors"]
    assert vendors[0]["vendor_project"] == "BigVendor"
    assert vendors[0]["count"] == 3


def test_stats_requires_auth(client: TestClient):
    """認証なしでは 403 を返すことを確認する。"""
    response = client.get("/api/vulnerabilities/stats")
    assert response.status_code == 403


# ── モデル repr テスト ────────────────────────────────────────────


def test_vulnerability_repr(db_session: Session):
    """Vulnerability の __repr__ が正しい文字列を返すことを確認する。"""
    vuln = _make_vuln(db_session, cve_id="CVE-2026-99999", vendor="ReprVendor")
    result = repr(vuln)
    assert "CVE-2026-99999" in result
    assert "ReprVendor" in result


# ── /admin/crawl テスト ───────────────────────────────────────────


def test_admin_crawl_requires_auth(client: TestClient):
    """POST /admin/crawl は API キーなしで 403 を返すことを確認する。"""
    response = client.post("/admin/crawl")
    assert response.status_code == 403


def test_admin_crawl_success(client: TestClient, monkeypatch):
    """POST /admin/crawl がクローラーを正常実行し結果を返すことを確認する。"""
    monkeypatch.setattr("app.auth.settings.API_KEY", TEST_API_KEY)
    with patch("app.main._fetch_cisa_kev", return_value=[]), \
         patch("app.main._upsert_vulnerabilities", return_value=(3, 1)):
        response = client.post(
            "/admin/crawl",
            headers={"X-API-KEY": TEST_API_KEY},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["inserted"] == 3
    assert body["updated"] == 1
    assert "completed" in body["message"].lower()


def test_admin_crawl_failure_returns_500(client: TestClient, monkeypatch):
    """クローラーが例外を送出した場合に 500 を返すことを確認する。"""
    monkeypatch.setattr("app.auth.settings.API_KEY", TEST_API_KEY)
    with patch("app.main._fetch_cisa_kev", side_effect=RuntimeError("Network error")):
        response = client.post(
            "/admin/crawl",
            headers={"X-API-KEY": TEST_API_KEY},
        )
    assert response.status_code == 500
