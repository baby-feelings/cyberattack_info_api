"""セキュリティ態勢の MCP ツール（Issue #422）のテスト。

各ツールが、(1) 一覧に出る・(2) 公開キーでは使えない・(3) user には本人所有のリポジトリだけが見える・
(4) 他人のリポジトリを指定すると拒否される、ことを確認する。
"""
# ruff: noqa: E501 - 試験データの表（1行に1件）を、読みやすい形で並べるため
import os
from datetime import UTC, datetime, timedelta

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

import pytest  # noqa: E402

from app.depscan.models import DependencyFinding  # noqa: E402
from app.external_monitor.models import SiteCheck  # noqa: E402
from app.finding_exceptions.models import FindingException  # noqa: E402
from app.github_alerts.models import GithubAlert  # noqa: E402
from app.mcp_server import gateway  # noqa: E402
from app.repo_audit.models import RepoAudit  # noqa: E402
from tests.mcp_server.test_mcp_server import (  # noqa: E402
    _ADMIN,
    _PUBLIC_KEY,
    _call,
    _mcp_headers,
    _rpc,
)
from tests.mcp_server.test_mcp_server import (
    mcp_client as _mcp_client_fixture,
)

# pytest のフィクスチャ（本物のルーターを載せた MCP クライアント）を、このモジュールでも使えるようにする
mcp_client = _mcp_client_fixture

NOW = datetime(2026, 10, 31, tzinfo=UTC)
TOOLS = (
    "list_runtimes", "get_sla_report", "list_finding_exceptions", "list_github_alerts",
    "compare_dependabot_and_depscan", "get_repo_audit", "get_site_monitor",
)


def _seed(db):
    for owner in ("alice", "bob"):
        repo = f"{owner}/app"
        db.add_all([
            DependencyFinding(
                repo_full_name=repo, ecosystem="npm", package_name="lodash", installed_version="4.0.0",
                osv_id="GHSA-1", severity="CRITICAL", summary="s", fixed_versions=[], cve_ids=[],
                manifest_path="package-lock.json", detected_at=NOW - timedelta(days=40)),
            FindingException(
                kind="dependency", repo_full_name=repo, finding_key="npm|lodash|GHSA-9", status="accepted",
                reason="修正版なし", approver=owner, expires_at=NOW + timedelta(days=30)),
            GithubAlert(kind="dependabot", repo_full_name=repo, number=1, severity="HIGH", title="t",
                        html_url="https://x/1", detail={"ecosystem": "npm", "package": "lodash", "ghsa_id": "GHSA-7"},
                        detected_at=NOW),
            RepoAudit(repo_full_name=repo, score=50, audited_at=NOW, snapshot={}, changes=[],
                      checks=[{"key": "k", "status": "ng"}]),
            SiteCheck(url=f"https://{owner}.example", source="homepage", repo_full_name=repo,
                      tls_days_left=5, findings=[{"rule": "r", "severity": "ERROR", "message": "m"}], checked_at=NOW),
        ])
    db.commit()


class TestToolList:
    def test_the_new_tools_are_listed_and_are_read_only(self, mcp_client):
        resp = _rpc(mcp_client, "tools/list", headers=_ADMIN)
        names = {t["name"] for t in resp.json()["result"]["tools"]}

        assert set(TOOLS) | {"export_vex"} <= names
        # 登録・解除・手動実行は、ツール化しない
        assert not any(n.startswith(("create_", "revoke_", "delete_", "trigger_")) for n in names)


class TestAccessControl:
    @pytest.mark.parametrize("tool", [*TOOLS, "export_vex"])
    def test_the_public_key_cannot_use_them(self, mcp_client, db_session, tool):
        _seed(db_session)
        args = {"repo": "alice/app"} if tool == "export_vex" else {}

        is_error, text = _call(mcp_client, tool, args, {"X-API-KEY": _PUBLIC_KEY})

        assert is_error and "MCP トークン" in text

    def test_a_user_sees_only_own_rows_in_every_tool(self, mcp_client, db_session):
        _seed(db_session)
        headers = _mcp_headers("alice")

        for tool, key in (("get_sla_report", "overdue"), ("list_finding_exceptions", "data"),
                          ("list_github_alerts", "data"), ("get_repo_audit", "data"), ("get_site_monitor", "data")):
            is_error, body = _call(mcp_client, tool, {}, headers)
            assert not is_error, tool
            assert body[key] and {r["repo_full_name"] for r in body[key]} == {"alice/app"}, tool

        is_error, body = _call(mcp_client, "compare_dependabot_and_depscan", {}, headers)
        assert not is_error
        assert {r["repo_full_name"] for k in ("both", "only_github", "only_depscan") for r in body[k]} == {"alice/app"}

    def test_an_admin_sees_everything(self, mcp_client, db_session):
        _seed(db_session)
        is_error, body = _call(mcp_client, "get_repo_audit", {}, _ADMIN)
        assert not is_error and {r["repo_full_name"] for r in body["data"]} == {"alice/app", "bob/app"}

    def test_other_users_repositories_are_refused_or_empty_never_leaked(self, mcp_client, db_session):
        _seed(db_session)
        headers = _mcp_headers("alice")

        # 対応状況は、他人のリポジトリの指定を、拒否する
        is_error, text = _call(mcp_client, "get_sla_report", {"repo": "bob/app"}, headers)
        assert is_error and "アクセス権" in text
        # 一覧は、本人所有に絞るため、他人のリポジトリを指定しても、空（存在も分からない）
        for tool in ("list_finding_exceptions", "list_github_alerts", "list_runtimes"):
            is_error, body = _call(mcp_client, tool, {"repo": "bob/app"}, headers)
            assert not is_error and body["data"] == [], tool

    def test_vex_export_is_limited_to_the_owner(self, mcp_client, db_session):
        _seed(db_session)
        db_session.add(DependencyFinding(
            repo_full_name="alice/app", ecosystem="npm", package_name="lodash", installed_version="4.0.0",
            osv_id="GHSA-9", severity="HIGH", summary="s", fixed_versions=[], cve_ids=[],
            manifest_path="p", detected_at=NOW))
        db_session.commit()

        is_error, doc = _call(mcp_client, "export_vex", {"repo": "alice/app"}, _mcp_headers("alice"))
        assert not is_error and doc["statements"][0]["vulnerability"]["name"] == "GHSA-9"
        cyclonedx = _call(mcp_client, "export_vex", {"repo": "alice/app", "format": "cyclonedx"}, _mcp_headers("alice"))[1]
        assert cyclonedx["bomFormat"] == "CycloneDX"

        is_error, text = _call(mcp_client, "export_vex", {"repo": "bob/app"}, _mcp_headers("alice"))
        assert is_error and "アクセス権" in text


class TestParameters:
    def test_filters_are_passed_through(self, mcp_client, db_session):
        _seed(db_session)
        headers = _mcp_headers("alice")

        only_code = _call(mcp_client, "list_finding_exceptions", {"kind": "code"}, headers)[1]
        only_issues = _call(mcp_client, "get_repo_audit", {"only_issues": True}, headers)[1]
        ok_sites = _call(mcp_client, "get_site_monitor", {"only_issues": True}, headers)[1]

        assert only_code["data"] == []
        assert only_issues["repos_with_issues"] == 1
        assert ok_sites["sites_with_issues"] == 1

    def test_runtimes_return_an_empty_list_when_nothing_is_detected(self, mcp_client):
        is_error, body = _call(mcp_client, "list_runtimes", {"needs_action": True}, _mcp_headers("alice"))
        assert not is_error and body["data"] == []


class TestOwnerGuardCoversTheNewShapes:
    def test_a_foreign_row_in_any_listed_key_fails_closed(self):
        from mcp.server.fastmcp.exceptions import ToolError

        from app.mcp_server.auth import Principal

        user = Principal(kind="user", username="alice")
        for key in gateway.OWNED_ROW_KEYS:
            with pytest.raises(ToolError):
                gateway.enforce_owner(user, {key: [{"repo_full_name": "bob/app"}]})
            gateway.enforce_owner(user, {key: [{"repo_full_name": "alice/app"}]})
        gateway.enforce_owner(Principal(kind="admin", username=None), {"data": [{"repo_full_name": "bob/app"}]})
