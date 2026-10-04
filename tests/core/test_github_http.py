"""app.core.github_http（認証ヘッダー・GitHubApi クライアント）のテスト。"""
from unittest.mock import MagicMock, patch

import httpx
import pytest

from app.core.github_http import GITHUB_API_BASE, GitHubApi, github_headers


def _client_cm(client: MagicMock) -> MagicMock:
    """`httpx.Client(...)` の戻り値（コンテキストマネージャ）を模擬する。"""
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=client)
    cm.__exit__ = MagicMock(return_value=False)
    return cm


def _ok(status: int = 200) -> MagicMock:
    """指定ステータスの模擬レスポンス。4xx/5xx は raise_for_status が HTTPStatusError を投げる。"""
    resp = MagicMock()
    resp.status_code = status
    resp.headers = {}
    if status >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"status {status}", request=MagicMock(), response=resp,
        )
    return resp


class TestGithubHeaders:
    def test_builds_bearer_auth_and_api_version(self):
        headers = github_headers("tok")
        assert headers["Authorization"] == "Bearer tok"
        assert headers["Accept"] == "application/vnd.github+json"
        assert headers["X-GitHub-Api-Version"] == "2022-11-28"


class TestGitHubApi:
    def test_opens_authenticated_client_with_timeout_and_closes_it(self):
        client = MagicMock()
        cm = _client_cm(client)
        with patch("app.core.github_http.httpx.Client", return_value=cm) as mock_cls:
            with GitHubApi("tok", timeout=12.0):
                pass

        kwargs = mock_cls.call_args.kwargs
        assert kwargs["timeout"] == 12.0
        assert kwargs["headers"]["Authorization"] == "Bearer tok"
        assert "follow_redirects" not in kwargs
        cm.__exit__.assert_called_once()

    def test_follow_redirects_is_passed_only_when_requested(self):
        cm = _client_cm(MagicMock())
        with patch("app.core.github_http.httpx.Client", return_value=cm) as mock_cls:
            with GitHubApi("tok", follow_redirects=True):
                pass
        assert mock_cls.call_args.kwargs["follow_redirects"] is True

    def test_get_prefixes_api_base_and_forwards_params(self):
        client = MagicMock()
        client.get.return_value = _ok()
        with patch("app.core.github_http.httpx.Client", return_value=_client_cm(client)):
            with GitHubApi("tok") as api:
                api.get("/repos/o/r/pulls", params={"state": "open"})

        client.get.assert_called_once_with(
            f"{GITHUB_API_BASE}/repos/o/r/pulls", params={"state": "open"},
        )

    def test_get_put_patch_retry_transient_errors(self):
        """冪等な get/put/patch は 503 の後に成功すればリトライで救われる。"""
        for verb in ("get", "put", "patch"):
            client = MagicMock()
            transient = _ok(503)
            getattr(client, verb).side_effect = [transient, _ok(200)]
            with patch("app.core.github_http.httpx.Client", return_value=_client_cm(client)), \
                 patch("app.core.retry.time.sleep"):
                with GitHubApi("tok") as api:
                    resp = getattr(api, verb)("/x")
            assert resp.status_code == 200, verb
            assert getattr(client, verb).call_count == 2, verb

    def test_post_does_not_retry_and_raises_on_http_error(self):
        client = MagicMock()
        client.post.return_value = _ok(503)
        with patch("app.core.github_http.httpx.Client", return_value=_client_cm(client)):
            with GitHubApi("tok") as api, pytest.raises(httpx.HTTPStatusError):
                api.post("/repos/o/r/issues", json={"title": "t"})

        client.post.assert_called_once()  # リトライしない（重複作成の防止）

    def test_delete_does_not_retry_or_raise(self):
        client = MagicMock()
        not_found = _ok(404)
        client.delete.return_value = not_found
        with patch("app.core.github_http.httpx.Client", return_value=_client_cm(client)):
            with GitHubApi("tok") as api:
                resp = api.delete("/repos/o/r/git/refs/heads/b")

        assert resp.status_code == 404
        client.delete.assert_called_once()
        not_found.raise_for_status.assert_not_called()  # 従来どおり例外にしない
