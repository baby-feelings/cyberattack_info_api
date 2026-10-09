"""app.mcp_server（リモート MCP サーバー）のテスト。

重点は「他の人に自分のリポジトリを見せない」こと:
- 認証なし・不正な鍵・通常のセッショントークンは 401
- PUBLIC_API_KEY（公開情報用の鍵）では DEPSCAN / CODESCAN が見えない
- MCP トークンのユーザーは、自分が所有するリポジトリの結果しか見えない
"""
import json
import os
from contextlib import asynccontextmanager
from datetime import date, datetime, timezone
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")
os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret-key-for-pytest")

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from mcp.server.fastmcp.exceptions import ToolError  # noqa: E402

from app.auth.mcp_token import create_mcp_token  # noqa: E402
from app.auth.session import create_session_token  # noqa: E402
from app.codescan.models import CodeFinding  # noqa: E402
from app.codescan.router import router as codescan_router  # noqa: E402
from app.core.database import get_db  # noqa: E402
from app.depscan.models import DependencyFinding  # noqa: E402
from app.depscan.router import router as depscan_router  # noqa: E402
from app.jvn.router import router as jvn_router  # noqa: E402
from app.kev.models import Vulnerability  # noqa: E402
from app.kev.router import router as kev_router  # noqa: E402
from app.mcp_server.auth import Principal  # noqa: E402
from app.mcp_server.server import MAX_PER_PAGE, McpServer, _clean, _enforce_owner  # noqa: E402
from app.osv.router import router as osv_router  # noqa: E402

_NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
_ADMIN = {"X-API-KEY": "test-api-key-for-pytest"}
_PUBLIC_KEY = "public-key-for-mcp-test"
_RPC_HEADERS = {"Accept": "application/json, text/event-stream"}


def _mcp_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_mcp_token(token)[0]}"}


def _depscan(db, repo: str, osv_id: str) -> None:
    db.add(DependencyFinding(
        repo_full_name=repo, ecosystem="npm", package_name="left-pad",
        installed_version="1.0.0", osv_id=osv_id, severity="HIGH", cvss_score=7.5,
        summary="s", fixed_versions=["1.0.1"], manifest_path="package-lock.json",
        detected_at=_NOW, resolved_at=None,
    ))
    db.commit()


def _codescan(db, repo: str, rule_id: str) -> None:
    db.add(CodeFinding(
        repo_full_name=repo, file_path="a.py", line_start=1, line_end=2, rule_id=rule_id,
        message="m", severity="ERROR", cvss_score=7.0, tool="semgrep", code_snippet="x",
        detected_at=_NOW, resolved_at=None,
    ))
    db.commit()


@pytest.fixture
def mcp_client(db_session):
    """本物のルーターだけを載せた使い捨てアプリに MCP サーバーを組み込んだクライアント。"""
    server = McpServer()

    @asynccontextmanager
    async def lifespan(_app):
        async with server.lifespan():
            yield

    test_app = FastAPI(lifespan=lifespan)
    for r in (kev_router, osv_router, jvn_router, depscan_router, codescan_router):
        test_app.include_router(r)
    server.mount(test_app)

    def override_get_db():
        yield db_session

    test_app.dependency_overrides[get_db] = override_get_db
    with patch("app.mcp_server.auth.settings.PUBLIC_API_KEY", _PUBLIC_KEY):
        with TestClient(test_app) as c:
            yield c


def _rpc(client, method: str, params: dict | None = None, headers: dict | None = None):
    return client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}},
        headers={**_RPC_HEADERS, **(headers or {})},
    )


def _call(client, tool: str, args: dict | None = None, headers: dict | None = None):
    """ツールを呼び、(エラーか, 結果の JSON) を返す。"""
    resp = _rpc(client, "tools/call", {"name": tool, "arguments": args or {}}, headers)
    assert resp.status_code == 200, resp.text
    result = resp.json()["result"]
    # 空リストを返したツールは content が空になる
    content = result["content"]
    text = content[0]["text"] if content else "[]"
    return result.get("isError", False), (text if result.get("isError") else json.loads(text))


class TestAuthentication:
    def test_rejects_missing_credentials(self, mcp_client):
        resp = _rpc(mcp_client, "tools/list")
        assert resp.status_code == 401
        assert resp.headers["www-authenticate"] == "Bearer"

    def test_rejects_wrong_api_key(self, mcp_client):
        assert _rpc(mcp_client, "tools/list", headers={"X-API-KEY": "wrong"}).status_code == 401

    def test_rejects_dashboard_session_token(self, mcp_client):
        # ダッシュボードのセッショントークンは MCP トークンとして使えない（用途が別）
        headers = {"Authorization": f"Bearer {create_session_token('alice')}"}
        assert _rpc(mcp_client, "tools/list", headers=headers).status_code == 401

    def test_rejects_garbage_bearer_token(self, mcp_client):
        headers = {"Authorization": "Bearer not-a-token"}
        assert _rpc(mcp_client, "tools/list", headers=headers).status_code == 401

    def test_public_key_is_accepted(self, mcp_client):
        resp = _rpc(mcp_client, "tools/list", headers={"X-API-KEY": _PUBLIC_KEY})
        assert resp.status_code == 200


class TestToolList:
    def test_lists_read_only_tools_and_no_admin_tools(self, mcp_client):
        resp = _rpc(mcp_client, "tools/list", headers=_ADMIN)
        names = {t["name"] for t in resp.json()["result"]["tools"]}
        assert {"search_kev", "get_kev", "search_osv", "list_depscan_findings",
                "list_codescan_findings", "whoami"} <= names
        # 管理系・書き込み系はツール化しない
        assert not any("crawl" in n or "admin" in n or "trigger" in n for n in names)


class TestPublicTools:
    def test_search_kev_returns_data(self, mcp_client, db_session):
        db_session.add(Vulnerability(
            cve_id="CVE-2026-1", vendor_project="Acme", product="Widget",
            vulnerability_name="n", description="d", required_action="a",
            date_added=date.today(),
        ))
        db_session.commit()
        is_error, body = _call(mcp_client, "search_kev", {"search": "Acme"},
                               {"X-API-KEY": _PUBLIC_KEY})
        assert not is_error
        assert body["total"] == 1
        assert body["data"][0]["cve_id"] == "CVE-2026-1"

    def test_get_kev_not_found_is_tool_error(self, mcp_client):
        is_error, text = _call(mcp_client, "get_kev", {"cve_id": "CVE-0000-0"}, _ADMIN)
        assert is_error
        assert "見つかりません" in text

    def test_user_token_can_read_public_data(self, mcp_client):
        is_error, _ = _call(mcp_client, "get_recent_kev", {"days": 7}, _mcp_headers("alice"))
        assert not is_error


class TestPrivateDataIsolation:
    def test_public_key_cannot_read_depscan_or_codescan(self, mcp_client, db_session):
        _depscan(db_session, "alice/app", "GHSA-1")
        _codescan(db_session, "alice/app", "rule.1")
        headers = {"X-API-KEY": _PUBLIC_KEY}
        for tool in ("list_depscan_findings", "get_depscan_stats",
                     "list_codescan_findings", "get_codescan_stats"):
            is_error, text = _call(mcp_client, tool, headers=headers)
            assert is_error, tool
            assert "MCP トークン" in text

    def test_user_sees_only_own_depscan(self, mcp_client, db_session):
        _depscan(db_session, "alice/app", "GHSA-1")
        _depscan(db_session, "bob/app", "GHSA-2")
        is_error, body = _call(mcp_client, "list_depscan_findings", {"resolved": False},
                               _mcp_headers("alice"))
        assert not is_error
        assert [f["repo_full_name"] for f in body["data"]] == ["alice/app"]

    def test_user_sees_only_own_codescan(self, mcp_client, db_session):
        _codescan(db_session, "alice/app", "rule.1")
        _codescan(db_session, "bob/app", "rule.2")
        is_error, body = _call(mcp_client, "list_codescan_findings", {"resolved": False},
                               _mcp_headers("alice"))
        assert not is_error
        assert [f["repo_full_name"] for f in body["data"]] == ["alice/app"]

    def test_user_cannot_query_other_users_repo(self, mcp_client, db_session):
        _depscan(db_session, "bob/app", "GHSA-2")
        _codescan(db_session, "bob/app", "rule.2")
        for tool in ("list_depscan_findings", "list_codescan_findings"):
            is_error, text = _call(mcp_client, tool, {"repo": "bob/app"}, _mcp_headers("alice"))
            assert is_error, tool
            assert "アクセス権" in text

    def test_user_stats_are_scoped(self, mcp_client, db_session):
        _depscan(db_session, "alice/app", "GHSA-1")
        _depscan(db_session, "bob/app", "GHSA-2")
        _codescan(db_session, "alice/app", "rule.1")
        _codescan(db_session, "bob/app", "rule.2")
        for tool in ("get_depscan_stats", "get_codescan_stats"):
            is_error, body = _call(mcp_client, tool, headers=_mcp_headers("alice"))
            assert not is_error
            assert [r["repo_full_name"] for r in body["repos"]] == ["alice/app"]
            assert body["total"] == 1

    def test_admin_sees_all(self, mcp_client, db_session):
        _depscan(db_session, "alice/app", "GHSA-1")
        _depscan(db_session, "bob/app", "GHSA-2")
        is_error, body = _call(mcp_client, "list_depscan_findings", headers=_ADMIN)
        assert not is_error
        assert body["total"] == 2


class TestWhoami:
    def test_reports_scope_per_principal(self, mcp_client):
        _, admin = _call(mcp_client, "whoami", headers=_ADMIN)
        _, public = _call(mcp_client, "whoami", headers={"X-API-KEY": _PUBLIC_KEY})
        _, user = _call(mcp_client, "whoami", headers=_mcp_headers("alice"))
        assert admin["access"] == "admin"
        assert public["access"] == "public"
        assert user["access"] == "user"
        assert user["username"] == "alice"
        assert "alice" in user["scope"]


class TestHelpers:
    def test_enforce_owner_fails_closed_when_foreign_repo_leaks(self):
        # REST の絞り込みが万一破れても、他人のリポジトリを含む応答は返さない
        payload = {"data": [{"repo_full_name": "alice/app"}, {"repo_full_name": "bob/app"}]}
        with pytest.raises(ToolError):
            _enforce_owner(Principal("user", "alice"), payload)

    def test_enforce_owner_checks_stats_repos(self):
        with pytest.raises(ToolError):
            _enforce_owner(Principal("user", "alice"), {"repos": [{"repo_full_name": "bob/x"}]})

    def test_enforce_owner_skips_admin(self):
        _enforce_owner(Principal("admin"), {"data": [{"repo_full_name": "bob/app"}]})

    def test_enforce_owner_does_not_match_prefix_of_other_user(self):
        # "alice" が "alice2/app" を見られないこと（"alice/" で前方一致）
        with pytest.raises(ToolError):
            _enforce_owner(Principal("user", "alice"), {"data": [{"repo_full_name": "alice2/app"}]})

    def test_clean_drops_none_and_caps_per_page(self):
        assert _clean({"a": None, "b": 1, "per_page": 9999}) == {"b": 1, "per_page": MAX_PER_PAGE}
        assert _clean({"per_page": 0})["per_page"] == 1


class TestLifecycle:
    def test_returns_503_outside_lifespan(self):
        server = McpServer()
        app = FastAPI()
        server.mount(app)
        resp = TestClient(app).post("/mcp", json={}, headers=_ADMIN)
        assert resp.status_code == 503
