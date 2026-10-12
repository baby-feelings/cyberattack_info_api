"""app.mcp_server.gateway（REST への窓口・認可の検証）のテスト。"""
import os

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")
os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret-key-for-pytest")

from mcp.server.fastmcp.exceptions import ToolError  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.mcp_server.auth import Principal  # noqa: E402
from app.mcp_server.gateway import (  # noqa: E402
    MAX_PER_PAGE,
    clean_params,
    credentials_for,
    enforce_owner,
)


class TestEnforceOwner:
    def test_fails_closed_when_foreign_repo_leaks(self):
        # REST の絞り込みが万一破れても、他人のリポジトリを含む応答は返さない
        payload = {"data": [{"repo_full_name": "alice/app"}, {"repo_full_name": "bob/app"}]}
        with pytest.raises(ToolError):
            enforce_owner(Principal("user", "alice"), payload)

    def test_checks_stats_repos(self):
        with pytest.raises(ToolError):
            enforce_owner(Principal("user", "alice"), {"repos": [{"repo_full_name": "bob/x"}]})

    def test_skips_admin(self):
        enforce_owner(Principal("admin"), {"data": [{"repo_full_name": "bob/app"}]})

    def test_does_not_match_prefix_of_other_user(self):
        # "alice" が "alice2/app" を見られないこと（"alice/" で前方一致）
        payload = {"data": [{"repo_full_name": "alice2/app"}]}
        with pytest.raises(ToolError):
            enforce_owner(Principal("user", "alice"), payload)

    def test_allows_own_repos(self):
        enforce_owner(Principal("user", "alice"), {"data": [{"repo_full_name": "alice/app"}]})


class TestCleanParams:
    def test_drops_none_and_caps_per_page(self):
        cleaned = clean_params({"a": None, "b": 1, "per_page": 9999})
        assert cleaned == {"b": 1, "per_page": MAX_PER_PAGE}

    def test_per_page_has_a_floor_of_one(self):
        assert clean_params({"per_page": 0})["per_page"] == 1


class TestCredentialsFor:
    def test_public_data_uses_the_api_key_for_everyone(self):
        for principal in (Principal("public"), Principal("user", "alice"), Principal("admin")):
            assert credentials_for(principal, private=False) == {"X-API-KEY": settings.API_KEY}

    def test_admin_uses_the_api_key_for_private_data(self):
        assert credentials_for(Principal("admin"), private=True) == {"X-API-KEY": settings.API_KEY}

    def test_user_gets_a_session_token_for_private_data(self):
        headers = credentials_for(Principal("user", "alice"), private=True)
        assert headers["Authorization"].startswith("Bearer ")
        assert "X-API-KEY" not in headers

    def test_public_principal_cannot_read_private_data(self):
        with pytest.raises(ToolError):
            credentials_for(Principal("public"), private=True)
