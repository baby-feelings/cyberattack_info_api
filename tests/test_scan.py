"""ライブラリ脆弱性スキャン API のテスト。

OSV API への外部通信は unittest.mock でモックし、
CISA KEV 検索はテスト DB を使って実際にクエリを実行する。
"""
from datetime import date
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from app.models import Vulnerability
from app.routers.scan import (
    _deduplicate,
    _extract_fixed_versions,
    _extract_severity,
    _parse_requirements,
    _query_kev,
    _query_osv,
)
from app.schemas import VulnerabilityFinding
from tests.conftest import TEST_API_KEY

# ── _extract_severity のテスト ────────────────────────────────────


def test_extract_severity_from_database_specific():
    """database_specific.severity が存在する場合はそれを返す。"""
    vuln = {"database_specific": {"severity": "critical"}}
    assert _extract_severity(vuln) == "CRITICAL"


def test_extract_severity_from_cvss_vector():
    """database_specific がない場合、CVSS ベクタから重要度を推定する。"""
    vuln = {
        "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
        ]
    }
    assert _extract_severity(vuln) == "HIGH"


def test_extract_severity_none_when_no_data():
    """重要度情報がない場合は None を返す。"""
    assert _extract_severity({}) is None


# ── _extract_fixed_versions のテスト ─────────────────────────────


def test_extract_fixed_versions_returns_fixed():
    """affected リストから正しくバージョンを抽出する。"""
    vuln = {
        "affected": [
            {
                "package": {"name": "fastapi"},
                "ranges": [
                    {"events": [{"introduced": "0"}, {"fixed": "0.109.1"}]}
                ],
            }
        ]
    }
    result = _extract_fixed_versions(vuln, "fastapi")
    assert result == ["0.109.1"]


def test_extract_fixed_versions_case_insensitive():
    """パッケージ名の大文字・小文字を無視して一致させる。"""
    vuln = {
        "affected": [
            {
                "package": {"name": "FastAPI"},
                "ranges": [{"events": [{"fixed": "1.0.0"}]}],
            }
        ]
    }
    assert _extract_fixed_versions(vuln, "fastapi") == ["1.0.0"]


def test_extract_fixed_versions_skips_other_packages():
    """別パッケージの fixed バージョンは含めない。"""
    vuln = {
        "affected": [
            {
                "package": {"name": "starlette"},
                "ranges": [{"events": [{"fixed": "0.36.2"}]}],
            }
        ]
    }
    assert _extract_fixed_versions(vuln, "fastapi") == []


# ── _parse_requirements のテスト ─────────────────────────────────


def test_parse_requirements_basic():
    """基本的な requirements.txt をパースできる。"""
    text = "fastapi==0.115.6\nhttpx==0.28.1\n"
    pkgs = _parse_requirements(text)
    names = [p.name for p in pkgs]
    versions = {p.name: p.version for p in pkgs}
    assert "fastapi" in names
    assert "httpx" in names
    assert versions["fastapi"] == "0.115.6"
    assert versions["httpx"] == "0.28.1"


def test_parse_requirements_skips_comments():
    """コメント行をスキップする。"""
    text = "# コメント\nfastapi==0.115.6\n"
    pkgs = _parse_requirements(text)
    assert len(pkgs) == 1
    assert pkgs[0].name == "fastapi"


def test_parse_requirements_skips_options():
    """-r や --index-url などのオプション行をスキップする。"""
    text = "-r base.txt\n--index-url https://pypi.org\nrequests==2.32.0\n"
    pkgs = _parse_requirements(text)
    assert len(pkgs) == 1
    assert pkgs[0].name == "requests"


def test_parse_requirements_no_version():
    """バージョン指定なし（>= のみ）の場合は version=None。"""
    text = "fastapi>=0.100.0\n"
    pkgs = _parse_requirements(text)
    assert pkgs[0].name == "fastapi"
    assert pkgs[0].version is None  # >= は == ではないため None


def test_parse_requirements_with_extras():
    """extras（例: uvicorn[standard]）付きパッケージを正しくパースする。"""
    text = "uvicorn[standard]==0.32.1\n"
    pkgs = _parse_requirements(text)
    assert pkgs[0].name == "uvicorn"
    assert pkgs[0].version == "0.32.1"


def test_parse_requirements_with_env_marker():
    """セミコロン以降の環境マーカーを除去する。"""
    text = 'pywin32==308; sys_platform == "win32"\n'
    pkgs = _parse_requirements(text)
    assert pkgs[0].name == "pywin32"


def test_parse_requirements_empty():
    """空文字列の場合は空リストを返す。"""
    assert _parse_requirements("") == []


# ── _deduplicate のテスト ────────────────────────────────────────


def test_deduplicate_removes_duplicates():
    """同一パッケージ × 同一 CVE ID の重複を除去する。"""
    f1 = VulnerabilityFinding(
        package_name="fastapi", package_version=None, source="OSV",
        vuln_id="CVE-2024-1234", summary="OSV finding",
    )
    f2 = VulnerabilityFinding(
        package_name="fastapi", package_version=None, source="CISA_KEV",
        vuln_id="CVE-2024-1234", summary="KEV finding",
    )
    result = _deduplicate([f1, f2])
    # OSV が優先されるため summary は OSV のもの
    assert len(result) == 1
    assert result[0].source == "OSV"


def test_deduplicate_keeps_different_vulns():
    """異なる CVE ID は重複として扱わない。"""
    f1 = VulnerabilityFinding(
        package_name="fastapi", package_version=None, source="OSV",
        vuln_id="CVE-2024-0001", summary="vuln 1",
    )
    f2 = VulnerabilityFinding(
        package_name="fastapi", package_version=None, source="OSV",
        vuln_id="CVE-2024-0002", summary="vuln 2",
    )
    assert len(_deduplicate([f1, f2])) == 2


def test_deduplicate_kev_prefers_osv():
    """CISA_KEV のみある場合は OSV に後から上書きされる。"""
    kev = VulnerabilityFinding(
        package_name="nginx", package_version=None, source="CISA_KEV",
        vuln_id="CVE-2024-9999", summary="KEV only",
    )
    osv = VulnerabilityFinding(
        package_name="nginx", package_version=None, source="OSV",
        vuln_id="CVE-2024-9999", summary="OSV detail",
    )
    result = _deduplicate([kev, osv])
    assert result[0].source == "OSV"
    assert result[0].summary == "OSV detail"


# ── _query_kev のテスト ──────────────────────────────────────────


def test_query_kev_finds_matching_product(db_session):
    """CISA KEV DB から製品名でヒットする脆弱性を返す。"""
    # テストデータを投入
    db_session.add(Vulnerability(
        cve_id="CVE-2024-5555",
        vendor_project="Apache Software Foundation",
        product="Log4j",
        vulnerability_name="Log4Shell RCE",
        description="Remote code execution in Log4j",
        required_action="Apply updates",
        date_added=date(2021, 12, 10),
    ))
    db_session.commit()

    results = _query_kev(db_session, "log4j")
    assert len(results) == 1
    assert results[0].vuln_id == "CVE-2024-5555"
    assert results[0].source == "CISA_KEV"


def test_query_kev_no_match(db_session):
    """一致しないパッケージ名には空リストを返す。"""
    results = _query_kev(db_session, "nonexistent-package-xyz")
    assert results == []


# ── _query_osv のテスト（OSV API をモック） ──────────────────────


OSV_MOCK_RESPONSE = {
    "vulns": [
        {
            "id": "GHSA-xxxx-yyyy-zzzz",
            "aliases": ["CVE-2024-0042"],
            "summary": "SQL injection in example-lib",
            "details": "Detailed description of the vulnerability.",
            "database_specific": {"severity": "HIGH"},
            "severity": [],
            "affected": [
                {
                    "package": {"name": "example-lib"},
                    "ranges": [
                        {"events": [{"introduced": "0"}, {"fixed": "2.0.1"}]}
                    ],
                }
            ],
            "references": [
                {"url": "https://example.com/advisory"},
            ],
        }
    ]
}


def test_query_osv_returns_findings():
    """OSV API レスポンスを正しく VulnerabilityFinding に変換する。"""
    mock_resp = MagicMock()
    mock_resp.json.return_value = OSV_MOCK_RESPONSE
    mock_resp.raise_for_status = MagicMock()

    with patch("app.routers.scan.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.post.return_value = mock_resp
        results = _query_osv("example-lib", "2.0.0", "PyPI")

    assert len(results) == 1
    assert results[0].vuln_id == "CVE-2024-0042"
    assert results[0].severity == "HIGH"
    assert results[0].fixed_versions == ["2.0.1"]
    assert results[0].source == "OSV"


def test_query_osv_empty_when_no_vulns():
    """脆弱性がない場合は空リストを返す。"""
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"vulns": []}
    mock_resp.raise_for_status = MagicMock()

    with patch("app.routers.scan.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.post.return_value = mock_resp
        results = _query_osv("safe-package", "1.0.0", "PyPI")

    assert results == []


def test_query_osv_handles_api_error():
    """OSV API エラー時は空リストを返し、例外を伝播させない。"""
    import httpx as httpx_module

    with patch("app.routers.scan.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.post.side_effect = (
            httpx_module.ConnectError("connection refused")
        )
        results = _query_osv("any-package", "1.0.0", "PyPI")

    assert results == []


# ── POST /api/scan エンドポイントのテスト ──────────────────────


def test_scan_packages_returns_200(client: TestClient):
    """パッケージスキャンが正常に完了し 200 を返す。"""
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"vulns": []}
    mock_resp.raise_for_status = MagicMock()

    with patch("app.routers.scan.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.post.return_value = mock_resp
        resp = client.post(
            "/api/scan",
            json={"packages": [{"name": "fastapi", "version": "0.115.6"}]},
            headers={"X-API-KEY": TEST_API_KEY},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["scanned_packages"] == 1
    assert "total_findings" in data
    assert isinstance(data["findings"], list)


def test_scan_packages_requires_auth(client: TestClient):
    """認証なしでは 403 を返す。"""
    resp = client.post(
        "/api/scan",
        json={"packages": [{"name": "fastapi"}]},
    )
    assert resp.status_code == 403


def test_scan_packages_combines_osv_and_kev(client: TestClient, db_session):
    """OSV と CISA KEV 両方から脆弱性を収集し、重複除去して返す。"""
    # CISA KEV にテストデータを投入
    db_session.add(Vulnerability(
        cve_id="CVE-2021-44228",
        vendor_project="Apache",
        product="Log4j",
        vulnerability_name="Log4Shell",
        description="RCE via JNDI lookup",
        required_action="Update",
        date_added=date(2021, 12, 10),
    ))
    db_session.commit()

    # OSV からは別の CVE を返す
    osv_resp = {
        "vulns": [
            {
                "id": "GHSA-test",
                "aliases": ["CVE-2021-45046"],
                "summary": "DoS in Log4j",
                "database_specific": {"severity": "MEDIUM"},
                "severity": [],
                "affected": [],
                "references": [],
            }
        ]
    }
    mock_resp = MagicMock()
    mock_resp.json.return_value = osv_resp
    mock_resp.raise_for_status = MagicMock()

    with patch("app.routers.scan.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.post.return_value = mock_resp
        resp = client.post(
            "/api/scan",
            json={"packages": [{"name": "log4j", "ecosystem": "Maven"}]},
            headers={"X-API-KEY": TEST_API_KEY},
        )

    assert resp.status_code == 200
    data = resp.json()
    sources = {f["source"] for f in data["findings"]}
    # OSV と CISA_KEV の両方が含まれる
    assert "OSV" in sources
    assert "CISA_KEV" in sources


# ── POST /api/scan/requirements エンドポイントのテスト ───────────


def test_scan_requirements_returns_200(client: TestClient):
    """requirements.txt スキャンが正常に完了し 200 を返す。"""
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"vulns": []}
    mock_resp.raise_for_status = MagicMock()

    reqs_text = "fastapi==0.115.6\nhttpx==0.28.1\n"

    with patch("app.routers.scan.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.post.return_value = mock_resp
        resp = client.post(
            "/api/scan/requirements",
            content=reqs_text,
            headers={
                "X-API-KEY": TEST_API_KEY,
                "Content-Type": "text/plain",
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data["scanned_packages"] == 2


def test_scan_requirements_empty_body(client: TestClient):
    """空の requirements.txt は 422 を返す。"""
    resp = client.post(
        "/api/scan/requirements",
        content="# comment only\n",
        headers={
            "X-API-KEY": TEST_API_KEY,
            "Content-Type": "text/plain",
        },
    )
    assert resp.status_code == 422


def test_scan_requirements_requires_auth(client: TestClient):
    """認証なしでは 403 を返す。"""
    resp = client.post(
        "/api/scan/requirements",
        content="fastapi==0.115.6\n",
        headers={"Content-Type": "text/plain"},
    )
    assert resp.status_code == 403
