"""依存ライブラリ脆弱性スキャン（DEPSCAN）機能のテスト。

GET /api/depscan・/api/depscan/stats・POST /admin/depscan-crawl など、API（router）のテスト。
クローラー・リポジトリ・ユーザースキャン等のユニットテストは、モジュールごとの test_*.py にある。
"""
import os
from datetime import UTC, datetime
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")


from app.auth.session import create_session_token  # noqa: E402
from app.depscan.models import RepoAssetContext  # noqa: E402
from app.kev.models import Vulnerability  # noqa: E402
from tests.depscan.support import make_finding  # noqa: E402

TEST_API_KEY = "test-api-key-for-pytest"
HEADERS = {"X-API-KEY": TEST_API_KEY}

_NOW = datetime.now(UTC)


_REPO = "app.core.github.repo.GitHubRepo"








# ──────────────────────────────────────────────────────────────
# GET /api/depscan
# ──────────────────────────────────────────────────────────────


class TestListDepscan:
    def test_empty(self, client):
        res = client.get("/api/depscan", headers=HEADERS)
        assert res.status_code == 200
        assert res.json()["total"] == 0

    def test_requires_auth(self, client):
        res = client.get("/api/depscan")
        assert res.status_code == 403

    def test_returns_record(self, client, db_session):
        make_finding(db_session)
        res = client.get("/api/depscan", headers=HEADERS)
        body = res.json()
        assert body["total"] == 1
        assert body["data"][0]["package_name"] == "cryptography"
        assert body["data"][0]["resolved_at"] is None

    def test_filter_by_repo(self, client, db_session):
        make_finding(db_session, repo_full_name="baby-feelings/repo-a", osv_id="GHSA-a")
        make_finding(db_session, repo_full_name="baby-feelings/repo-b", osv_id="GHSA-b")
        res = client.get("/api/depscan?repo=baby-feelings/repo-a", headers=HEADERS)
        body = res.json()
        assert body["total"] == 1
        assert body["data"][0]["repo_full_name"] == "baby-feelings/repo-a"

    def test_filter_by_owner(self, client, db_session):
        make_finding(db_session, repo_full_name="baby-feelings/repo-a", osv_id="GHSA-a")
        make_finding(db_session, repo_full_name="other-owner/repo-b", osv_id="GHSA-b")
        res = client.get("/api/depscan?owner=baby-feelings", headers=HEADERS)
        body = res.json()
        assert body["total"] == 1
        assert body["data"][0]["repo_full_name"] == "baby-feelings/repo-a"

    def test_filter_by_owner_does_not_match_substring(self, client, db_session):
        """`owner` はリポジトリオーナー単位の一致（前方一致 + '/'）で、部分文字列一致ではない。"""
        make_finding(db_session, repo_full_name="baby-feelings-fork/repo-a", osv_id="GHSA-a")
        res = client.get("/api/depscan?owner=baby-feelings", headers=HEADERS)
        assert res.json()["total"] == 0

    def test_filter_by_ecosystem(self, client, db_session):
        make_finding(db_session, ecosystem="PyPI", osv_id="GHSA-py")
        make_finding(db_session, ecosystem="npm", package_name="axios", osv_id="GHSA-npm")
        res = client.get("/api/depscan?ecosystem=npm", headers=HEADERS)
        body = res.json()
        assert body["total"] == 1
        assert body["data"][0]["ecosystem"] == "npm"

    def test_filter_by_severity_case_insensitive(self, client, db_session):
        make_finding(db_session, severity="CRITICAL", osv_id="GHSA-crit")
        res = client.get("/api/depscan?severity=critical", headers=HEADERS)
        assert res.json()["total"] == 1

    def test_filter_by_resolved(self, client, db_session):
        make_finding(db_session, osv_id="GHSA-open")
        make_finding(db_session, osv_id="GHSA-resolved", resolved_at=_NOW)
        res_open = client.get("/api/depscan?resolved=false", headers=HEADERS)
        res_resolved = client.get("/api/depscan?resolved=true", headers=HEADERS)
        assert res_open.json()["total"] == 1
        assert res_resolved.json()["total"] == 1
        assert res_resolved.json()["data"][0]["osv_id"] == "GHSA-resolved"

    def test_pagination(self, client, db_session):
        for i in range(3):
            make_finding(db_session, osv_id=f"GHSA-{i}")
        res = client.get("/api/depscan?per_page=2&page=1", headers=HEADERS)
        assert len(res.json()["data"]) == 2

    def test_session_token_forces_owner_scope(self, client, db_session):
        """セッショントークン認証時、owner指定に関わらずログインユーザー本人のみに絞り込まれる。"""
        make_finding(db_session, repo_full_name="octocat/repo-a", osv_id="GHSA-mine")
        make_finding(db_session, repo_full_name="baby-feelings/baby_grow", osv_id="GHSA-others")
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("octocat")
            res = client.get(
                "/api/depscan?owner=baby-feelings",
                headers={"Authorization": f"Bearer {token}"},
            )
        body = res.json()
        assert body["total"] == 1
        assert body["data"][0]["repo_full_name"] == "octocat/repo-a"

    def test_session_token_rejects_mismatched_repo_param(self, client, db_session):
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("octocat")
            res = client.get(
                "/api/depscan?repo=baby-feelings/baby_grow",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert res.status_code == 403

    def test_invalid_session_token_and_no_api_key_returns_403(self, client):
        res = client.get(
            "/api/depscan", headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert res.status_code == 403

    def test_returns_repo_visibility(self, client, db_session):
        """Issue #131: repo_visibilityフィールドがそのまま返ること。"""
        make_finding(db_session, repo_visibility="private")
        res = client.get("/api/depscan", headers=HEADERS)
        assert res.json()["data"][0]["repo_visibility"] == "private"

    def test_asset_context_null_when_not_configured(self, client, db_session):
        """Issue #131: 資産コンテキスト未設定のリポジトリはnullを返すこと。"""
        make_finding(db_session)
        res = client.get("/api/depscan", headers=HEADERS)
        assert res.json()["data"][0]["asset_context"] is None

    def test_asset_context_attached_when_configured(self, client, db_session):
        """Issue #131: 設定済みの資産コンテキストが検知結果に埋め込まれること。"""
        from app.depscan.models import RepoAssetContext

        make_finding(db_session, repo_full_name="baby-feelings/prod-app", osv_id="GHSA-ctx")
        db_session.add(RepoAssetContext(
            repo_full_name="baby-feelings/prod-app",
            is_production=True,
            is_internet_facing=True,
            importance="high",
        ))
        db_session.commit()

        res = client.get("/api/depscan", headers=HEADERS)
        ctx = res.json()["data"][0]["asset_context"]
        assert ctx["is_production"] is True
        assert ctx["is_internet_facing"] is True
        assert ctx["importance"] == "high"


class TestDepscanStats:
    def test_empty(self, client):
        res = client.get("/api/depscan/stats", headers=HEADERS)
        assert res.status_code == 200
        assert res.json()["total"] == 0

    def test_requires_auth(self, client):
        res = client.get("/api/depscan/stats")
        assert res.status_code == 403

    def test_counts_unresolved_only(self, client, db_session):
        make_finding(db_session, repo_full_name="baby-feelings/repo-a", osv_id="GHSA-open")
        make_finding(
            db_session, repo_full_name="baby-feelings/repo-a",
            osv_id="GHSA-resolved", resolved_at=_NOW,
        )
        res = client.get("/api/depscan/stats", headers=HEADERS)
        body = res.json()
        assert body["total"] == 1
        assert body["repos"] == [{"repo_full_name": "baby-feelings/repo-a", "count": 1}]

    def test_session_token_forces_owner_scope(self, client, db_session):
        make_finding(db_session, repo_full_name="octocat/repo-a", osv_id="GHSA-mine")
        make_finding(db_session, repo_full_name="baby-feelings/baby_grow", osv_id="GHSA-others")
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("octocat")
            res = client.get(
                "/api/depscan/stats", headers={"Authorization": f"Bearer {token}"},
            )
        body = res.json()
        assert body["total"] == 1
        assert body["repos"] == [{"repo_full_name": "octocat/repo-a", "count": 1}]


# ──────────────────────────────────────────────────────────────
# POST /admin/depscan-crawl
# ──────────────────────────────────────────────────────────────


class TestAdminDepscanCrawl:
    def test_trigger_depscan_crawl(self, client):
        with patch("app.depscan.router.fetch_and_scan_dependencies", return_value=(0, 0, 0)):
            res = client.post("/admin/depscan-crawl", headers=HEADERS)
        assert res.status_code == 202
        assert "background" in res.json()["message"].lower()

    def test_requires_auth(self, client):
        res = client.post("/admin/depscan-crawl")
        assert res.status_code == 403

    def test_force_query_param_is_passed_through(self, client):
        """?force=true が fetch_and_scan_dependencies(force=True) に渡ること（Issue #239）。"""
        with patch(
            "app.depscan.router.run_in_background", side_effect=lambda name, fn: fn(),
        ), patch(
            "app.depscan.router.fetch_and_scan_dependencies", return_value=(0, 0, 0),
        ) as mock_fetch:
            res = client.post("/admin/depscan-crawl?force=true", headers=HEADERS)
        assert res.status_code == 202
        mock_fetch.assert_called_once_with(force=True)


# ──────────────────────────────────────────────────────────────
# GET /api/depscan/assets, PUT /admin/depscan/assets/{owner}/{repo}
# （Issue #131: リポジトリ資産コンテキスト）
# ──────────────────────────────────────────────────────────────


class TestListAssetContexts:
    def test_requires_auth(self, client):
        res = client.get("/api/depscan/assets")
        assert res.status_code == 403

    def test_empty(self, client):
        res = client.get("/api/depscan/assets", headers=HEADERS)
        assert res.status_code == 200
        assert res.json()["data"] == []

    def test_returns_configured_contexts(self, client, db_session):
        from app.depscan.models import RepoAssetContext

        db_session.add(RepoAssetContext(
            repo_full_name="baby-feelings/prod-app",
            is_production=True,
            is_internet_facing=True,
            importance="high",
        ))
        db_session.commit()

        res = client.get("/api/depscan/assets", headers=HEADERS)
        data = res.json()["data"]
        assert len(data) == 1
        assert data[0]["repo_full_name"] == "baby-feelings/prod-app"
        assert data[0]["is_production"] is True
        assert data[0]["importance"] == "high"


class TestSetAssetContext:
    def test_requires_auth(self, client):
        res = client.put(
            "/admin/depscan/assets/baby-feelings/prod-app",
            json={"is_production": True, "is_internet_facing": True, "importance": "high"},
        )
        assert res.status_code == 403

    def test_creates_new_context(self, client, db_session):
        res = client.put(
            "/admin/depscan/assets/baby-feelings/prod-app",
            headers=HEADERS,
            json={"is_production": True, "is_internet_facing": False, "importance": "medium"},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["repo_full_name"] == "baby-feelings/prod-app"
        assert body["is_production"] is True
        assert body["is_internet_facing"] is False
        assert body["importance"] == "medium"

        from app.depscan.models import RepoAssetContext
        row = db_session.query(RepoAssetContext).filter_by(
            repo_full_name="baby-feelings/prod-app",
        ).first()
        assert row is not None
        assert row.importance == "medium"

    def test_upserts_existing_context(self, client, db_session):
        from app.depscan.models import RepoAssetContext

        db_session.add(RepoAssetContext(
            repo_full_name="baby-feelings/prod-app",
            is_production=False,
            is_internet_facing=False,
            importance=None,
        ))
        db_session.commit()

        res = client.put(
            "/admin/depscan/assets/baby-feelings/prod-app",
            headers=HEADERS,
            json={"is_production": True, "is_internet_facing": True, "importance": "high"},
        )
        assert res.status_code == 200

        rows = db_session.query(RepoAssetContext).filter_by(
            repo_full_name="baby-feelings/prod-app",
        ).all()
        assert len(rows) == 1  # 新規行が増えず上書きされること
        assert rows[0].is_production is True
        assert rows[0].importance == "high"

    def test_rejects_invalid_importance(self, client):
        res = client.put(
            "/admin/depscan/assets/baby-feelings/prod-app",
            headers=HEADERS,
            json={"is_production": True, "is_internet_facing": True, "importance": "critical"},
        )
        assert res.status_code == 422

    def test_defaults_when_fields_omitted(self, client):
        res = client.put(
            "/admin/depscan/assets/baby-feelings/prod-app", headers=HEADERS, json={},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["is_production"] is False
        assert body["is_internet_facing"] is False
        assert body["importance"] is None


# ──────────────────────────────────────────────────────────────
# app.depscan.router: 優先度理由（priority_reasons、Issue #135）
# ──────────────────────────────────────────────────────────────


# app.depscan.priority のユニットテスト（_fetch_kev_map・_compute_priority_reasons）は
# tests/depscan/test_priority.py に移動済み。GET /api/depscan 経由の統合テストのみ以下に残す。


class TestListDepscanPriorityReasons:
    """GET /api/depscan の priority_reasons フィールド（統合テスト）。"""

    def test_empty_list_when_no_signals(self, client, db_session):
        make_finding(db_session)
        res = client.get("/api/depscan", headers=HEADERS)
        assert res.json()["data"][0]["priority_reasons"] == []

    def test_includes_kev_listed_for_matching_cve(self, client, db_session):
        db_session.add(Vulnerability(
            cve_id="CVE-2024-0001", vendor_project="V", product="P",
            vulnerability_name="n", description="d", required_action=None,
            date_added=_NOW.date(), epss_score=0.8,
        ))
        db_session.commit()
        make_finding(db_session, cve_ids=["CVE-2024-0001"])

        res = client.get("/api/depscan", headers=HEADERS)
        reasons = res.json()["data"][0]["priority_reasons"]
        assert "kev_listed" in reasons
        assert "epss_high" in reasons

    def test_includes_asset_context_reasons(self, client, db_session):
        make_finding(db_session, repo_full_name="baby-feelings/prod-app")
        db_session.add(RepoAssetContext(
            repo_full_name="baby-feelings/prod-app",
            is_production=True, is_internet_facing=True, importance="high",
        ))
        db_session.commit()

        res = client.get("/api/depscan", headers=HEADERS)
        reasons = res.json()["data"][0]["priority_reasons"]
        assert set(reasons) == {
            "internet_facing_asset", "production_asset", "high_importance_asset",
        }


class TestListDepscanPurl:
    """GET /api/depscan の purl フィールド（Issue #133、統合テスト）。"""

    def test_includes_purl(self, client, db_session):
        make_finding(db_session, ecosystem="PyPI", package_name="cryptography",
                       installed_version="3.4.7")
        res = client.get("/api/depscan", headers=HEADERS)
        assert res.json()["data"][0]["purl"] == "pkg:pypi/cryptography@3.4.7"


# ──────────────────────────────────────────────────────────────
# GET /api/depscan/export（SBOMエクスポート、Issue #133）
# ──────────────────────────────────────────────────────────────


class TestExportDepscanSbom:
    def test_requires_auth(self, client):
        res = client.get("/api/depscan/export?repo=baby-feelings/baby_grow")
        assert res.status_code == 403

    def test_requires_repo_param(self, client):
        res = client.get("/api/depscan/export", headers=HEADERS)
        assert res.status_code == 422

    def test_cyclonedx_export(self, client, db_session):
        make_finding(db_session)
        res = client.get(
            "/api/depscan/export?repo=baby-feelings/baby_grow&format=cyclonedx",
            headers=HEADERS,
        )
        assert res.status_code == 200
        assert res.headers["content-type"] == "application/vnd.cyclonedx+json"
        body = res.json()
        assert body["bomFormat"] == "CycloneDX"
        assert len(body["components"]) == 1

    def test_spdx_export(self, client, db_session):
        make_finding(db_session)
        res = client.get(
            "/api/depscan/export?repo=baby-feelings/baby_grow&format=spdx",
            headers=HEADERS,
        )
        assert res.status_code == 200
        assert res.headers["content-type"] == "application/spdx+json"
        body = res.json()
        assert body["spdxVersion"] == "SPDX-2.3"
        assert len(body["packages"]) == 1

    def test_defaults_to_cyclonedx_when_format_omitted(self, client, db_session):
        make_finding(db_session)
        res = client.get(
            "/api/depscan/export?repo=baby-feelings/baby_grow", headers=HEADERS,
        )
        assert res.json()["bomFormat"] == "CycloneDX"

    def test_rejects_unknown_format(self, client):
        res = client.get(
            "/api/depscan/export?repo=baby-feelings/baby_grow&format=xml", headers=HEADERS,
        )
        assert res.status_code == 422

    def test_only_includes_matching_repo(self, client, db_session):
        make_finding(db_session, repo_full_name="baby-feelings/repo-a", osv_id="GHSA-a")
        make_finding(db_session, repo_full_name="baby-feelings/repo-b", osv_id="GHSA-b")
        res = client.get(
            "/api/depscan/export?repo=baby-feelings/repo-a", headers=HEADERS,
        )
        body = res.json()
        assert len(body["vulnerabilities"]) == 1
        assert body["vulnerabilities"][0]["id"] == "GHSA-a"

    def test_filters_by_resolved(self, client, db_session):
        make_finding(db_session, osv_id="GHSA-open", resolved_at=None)
        make_finding(db_session, osv_id="GHSA-resolved", resolved_at=_NOW)
        res = client.get(
            "/api/depscan/export?repo=baby-feelings/baby_grow&resolved=false",
            headers=HEADERS,
        )
        body = res.json()
        assert len(body["vulnerabilities"]) == 1
        assert body["vulnerabilities"][0]["id"] == "GHSA-open"

    def test_filters_by_resolved_true(self, client, db_session):
        make_finding(db_session, osv_id="GHSA-open", resolved_at=None)
        make_finding(db_session, osv_id="GHSA-resolved", resolved_at=_NOW)
        res = client.get(
            "/api/depscan/export?repo=baby-feelings/baby_grow&resolved=true",
            headers=HEADERS,
        )
        body = res.json()
        assert len(body["vulnerabilities"]) == 1
        assert body["vulnerabilities"][0]["id"] == "GHSA-resolved"

    def test_empty_repo_produces_empty_sbom(self, client):
        res = client.get(
            "/api/depscan/export?repo=baby-feelings/no-findings", headers=HEADERS,
        )
        assert res.status_code == 200
        assert res.json()["components"] == []

    def test_session_token_forces_owner_scope(self, client, db_session):
        make_finding(db_session, repo_full_name="octocat/repo-a", osv_id="GHSA-mine")
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("octocat")
            res = client.get(
                "/api/depscan/export?repo=octocat/repo-a",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert res.status_code == 200

    def test_session_token_rejects_other_owners_repo(self, client, db_session):
        make_finding(db_session, repo_full_name="baby-feelings/baby_grow")
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("octocat")
            res = client.get(
                "/api/depscan/export?repo=baby-feelings/baby_grow",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert res.status_code == 403


class TestExportDepscanSbomInventory:
    """content=inventory（依存の全量）のエクスポート。"""

    def _add_inventory(self, db_session, repo="baby-feelings/baby_grow"):
        from app.depscan.models import RepoDependency

        db_session.add_all([
            RepoDependency(
                repo_full_name=repo, ecosystem="PyPI", package_name="cryptography",
                version="3.4.7", manifest_path="requirements.txt",
            ),
            RepoDependency(
                repo_full_name=repo, ecosystem="PyPI", package_name="httpx",
                version="0.28.1", manifest_path="requirements.txt",
            ),
        ])
        db_session.commit()

    def test_inventory_includes_dependencies_without_findings(self, client, db_session):
        make_finding(db_session)
        self._add_inventory(db_session)
        res = client.get(
            "/api/depscan/export?repo=baby-feelings/baby_grow&content=inventory",
            headers=HEADERS,
        )
        assert res.status_code == 200
        body = res.json()
        assert len(body["components"]) == 2
        assert len(body["vulnerabilities"]) == 1

    def test_inventory_spdx(self, client, db_session):
        self._add_inventory(db_session)
        res = client.get(
            "/api/depscan/export?repo=baby-feelings/baby_grow&format=spdx&content=inventory",
            headers=HEADERS,
        )
        assert res.status_code == 200
        assert len(res.json()["packages"]) == 2

    def test_default_content_is_findings_only(self, client, db_session):
        make_finding(db_session)
        self._add_inventory(db_session)
        res = client.get("/api/depscan/export?repo=baby-feelings/baby_grow", headers=HEADERS)
        assert len(res.json()["components"]) == 1

    def test_inventory_of_other_repo_is_not_mixed_in(self, client, db_session):
        self._add_inventory(db_session, repo="baby-feelings/other")
        res = client.get(
            "/api/depscan/export?repo=baby-feelings/baby_grow&content=inventory",
            headers=HEADERS,
        )
        assert res.json()["components"] == []

    def test_invalid_content_is_rejected(self, client):
        res = client.get(
            "/api/depscan/export?repo=baby-feelings/baby_grow&content=all", headers=HEADERS,
        )
        assert res.status_code == 422

    def test_session_token_rejects_other_owners_inventory(self, client, db_session):
        """全量モードでも、他人のリポジトリは取得できないこと。"""
        self._add_inventory(db_session)
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("octocat")
            res = client.get(
                "/api/depscan/export?repo=baby-feelings/baby_grow&content=inventory",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert res.status_code == 403


# ──────────────────────────────────────────────────────────────
# app.depscan.crawler
# ──────────────────────────────────────────────────────────────






















# app.depscan.issue_management のテスト（_file_github_issues・
# _close_resolved_repo_issues）は tests/depscan/test_issue_management.py に移動済み。


# ──────────────────────────────────────────────────────────────
# app.depscan.user_scan.run_depscan_for_user / get_user_scan_status
# ──────────────────────────────────────────────────────────────








