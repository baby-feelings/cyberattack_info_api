"""app.auth.github_oauth（GitHub OAuth クライアント）のテスト。"""
import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")

import pytest  # noqa: E402

from app.auth.github_oauth import (  # noqa: E402
    build_authorize_url,
    exchange_code_for_token,
    get_authenticated_user_login,
)


def _mock_httpx_client(get_return=None, post_return=None):
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    if get_return is not None:
        mock_client.get = MagicMock(return_value=get_return)
    if post_return is not None:
        mock_client.post = MagicMock(return_value=post_return)
    return mock_client


def _mock_response(json_data):
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = json_data
    return resp


class TestBuildAuthorizeUrl:
    def test_includes_required_params(self):
        url = build_authorize_url("client-123", "https://api.example.com/cb", "state-abc")
        assert url.startswith("https://github.com/login/oauth/authorize?")
        assert "client_id=client-123" in url
        assert "state=state-abc" in url
        assert "scope=repo" in url


class TestExchangeCodeForToken:
    def test_returns_access_token(self):
        mock_client = _mock_httpx_client(post_return=_mock_response({"access_token": "gho_abc"}))
        with patch("app.auth.github_oauth.httpx.Client", return_value=mock_client):
            token = exchange_code_for_token("id", "secret", "code123", "https://cb")
        assert token == "gho_abc"

    def test_missing_access_token_raises(self):
        mock_client = _mock_httpx_client(
            post_return=_mock_response({"error": "bad_verification_code"})
        )
        with patch("app.auth.github_oauth.httpx.Client", return_value=mock_client):
            with pytest.raises(ValueError):
                exchange_code_for_token("id", "secret", "bad-code", "https://cb")


class TestGetAuthenticatedUserLogin:
    def test_returns_login(self):
        mock_client = _mock_httpx_client(get_return=_mock_response({"login": "octocat", "id": 1}))
        with patch("app.auth.github_oauth.httpx.Client", return_value=mock_client):
            login = get_authenticated_user_login("gho_abc")
        assert login == "octocat"
