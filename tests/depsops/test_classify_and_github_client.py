"""バージョン分類（classify）と GitHub API クライアント（github_client）のテスト。
外部HTTP通信は全てモックする。
"""
import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

import httpx  # noqa: E402
import pytest  # noqa: E402

from app.core.github.repo import GitHubRepo  # noqa: E402
from app.depsops.classify import classify_bump  # noqa: E402
from app.depsops.github_client import (  # noqa: E402
    get_pull_request,
    has_ci_workflows,
    list_open_dependabot_alerts,
    list_open_dependabot_prs,
    merge_pull_request,
    request_rebase,
)

TEST_API_KEY = "test-api-key-for-pytest"
HEADERS = {"X-API-KEY": TEST_API_KEY}


def _mock_httpx_client(get_return=None, put_return=None, post_return=None, delete_return=None):
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    if get_return is not None:
        mock_client.get = MagicMock(return_value=get_return)
    if put_return is not None:
        mock_client.put = MagicMock(return_value=put_return)
    if post_return is not None:
        mock_client.post = MagicMock(return_value=post_return)
    if delete_return is not None:
        mock_client.delete = MagicMock(return_value=delete_return)
    return mock_client


def _mock_response(json_data, status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.raise_for_status = MagicMock()
    resp.json.return_value = json_data
    return resp


# ──────────────────────────────────────────────────────────────
# app.depsops.classify
# ──────────────────────────────────────────────────────────────


class TestClassifyBump:
    def test_minor_bump(self):
        assert classify_bump("chore(deps): bump lucide-react from 1.18.0 to 1.37.0") \
            == "minor_or_patch"

    def test_patch_bump(self):
        assert classify_bump("Bump webrick from 1.9.1 to 1.9.2") == "minor_or_patch"

    def test_major_bump(self):
        assert classify_bump("chore(deps-dev): Bump typescript from 6.0.3 to 7.0.2") == "major"

    def test_zero_x_minor_change_treated_as_major(self):
        """0.x系はminorの変化も破壊的変更扱いにする（semverの慣習）。"""
        assert classify_bump("Bump foo from 0.32.1 to 0.52.4") == "major"

    def test_requirement_style_with_operators(self):
        assert classify_bump(
            "chore(deps): Update pyyaml requirement from >=6.0.2 to >=6.0.3"
        ) == "minor_or_patch"

    def test_no_version_pattern_is_unknown(self):
        assert classify_bump(
            "chore(deps): Bump react-dom and @types/react-dom in /dashboard"
        ) == "unknown"

    def test_non_numeric_version_in_from_to_is_unknown(self):
        """"from X to Y" は一致するが、Xが数値バージョンでないケース。"""
        assert classify_bump("Bump foo from latest to stable") == "unknown"


# ──────────────────────────────────────────────────────────────
# app.depsops.github_client
# ──────────────────────────────────────────────────────────────


class TestListOpenDependabotPrs:
    def test_filters_to_dependabot_author(self):
        prs = [
            {"number": 1, "title": "bump x", "user": {"login": "dependabot[bot]"}},
            {"number": 2, "title": "feat: y", "user": {"login": "someone"}},
        ]
        mock_client = _mock_httpx_client(get_return=_mock_response(prs))
        with patch("httpx.Client", return_value=mock_client):
            result = list_open_dependabot_prs(GitHubRepo("owner", "repo", "token"))
        assert [pr["number"] for pr in result] == [1]

    def test_retries_on_rate_limit_403_then_succeeds(self):
        """レート制限由来の403（X-RateLimit-Remaining: 0）はリトライされること。
        権限不足の403（ヘッダー無し）と区別する（Issue #130）。"""
        prs = [{"number": 1, "title": "bump x", "user": {"login": "dependabot[bot]"}}]
        request = httpx.Request("GET", "https://api.github.com")
        rate_limited = httpx.Response(
            403,
            headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "0"},
            request=request,
        )
        mock_client = _mock_httpx_client()
        mock_client.get = MagicMock(side_effect=[rate_limited, _mock_response(prs)])
        with patch("httpx.Client", return_value=mock_client), \
             patch("app.core.net.retry.time.sleep"):
            result = list_open_dependabot_prs(GitHubRepo("owner", "repo", "token"))
        assert [pr["number"] for pr in result] == [1]
        assert mock_client.get.call_count == 2

    def test_does_not_retry_on_permission_403(self):
        """権限不足の403（レート制限ヘッダー無し）は即座に伝播すること。"""
        request = httpx.Request("GET", "https://api.github.com")
        forbidden = httpx.Response(403, request=request)
        mock_client = _mock_httpx_client(get_return=forbidden)
        with patch("httpx.Client", return_value=mock_client):
            with pytest.raises(httpx.HTTPStatusError):
                list_open_dependabot_prs(GitHubRepo("owner", "repo", "token"))
        mock_client.get.assert_called_once()


class TestGetPullRequest:
    def test_returns_detail(self):
        mock_client = _mock_httpx_client(
            get_return=_mock_response({"number": 1, "mergeable_state": "clean"})
        )
        with patch("httpx.Client", return_value=mock_client):
            result = get_pull_request(GitHubRepo("owner", "repo", "token"), 1)
        assert result["mergeable_state"] == "clean"


class TestMergePullRequest:
    def test_merges_and_deletes_branch(self):
        mock_client = _mock_httpx_client(
            put_return=_mock_response({"merged": True}),
            get_return=_mock_response({"head": {"ref": "dependabot/npm/foo"}}),
            delete_return=_mock_response({}),
        )
        with patch("httpx.Client", return_value=mock_client):
            result = merge_pull_request(GitHubRepo("owner", "repo", "token"), 1)
        assert result == {"merged": True}
        mock_client.delete.assert_called_once()
        assert "dependabot/npm/foo" in mock_client.delete.call_args[0][0]

    def test_branch_delete_failure_does_not_raise(self):
        mock_client = _mock_httpx_client(
            put_return=_mock_response({"merged": True}),
            get_return=_mock_response({"head": {"ref": "dependabot/npm/foo"}}),
        )
        mock_client.delete = MagicMock(
            side_effect=httpx.HTTPStatusError("404", request=MagicMock(), response=MagicMock())
        )
        with patch("httpx.Client", return_value=mock_client):
            result = merge_pull_request(GitHubRepo("owner", "repo", "token"), 1)
        assert result == {"merged": True}


class TestRequestRebase:
    def test_posts_rebase_comment(self):
        mock_client = _mock_httpx_client(post_return=_mock_response({}))
        with patch("httpx.Client", return_value=mock_client):
            request_rebase(GitHubRepo("owner", "repo", "token"), 1)
        assert mock_client.post.call_args.kwargs["json"] == {"body": "@dependabot rebase"}


class TestHasCiWorkflows:
    def test_returns_true_when_workflows_exist(self):
        mock_client = _mock_httpx_client(
            get_return=_mock_response([{"name": "ci.yml"}], status_code=200)
        )
        with patch("httpx.Client", return_value=mock_client):
            assert has_ci_workflows(GitHubRepo("owner", "repo", "token")) is True

    def test_returns_false_on_404(self):
        resp = _mock_response({"message": "Not Found"}, status_code=404)
        mock_client = _mock_httpx_client(get_return=resp)
        with patch("httpx.Client", return_value=mock_client):
            assert has_ci_workflows(GitHubRepo("owner", "repo", "token")) is False

    def test_returns_false_on_real_404_response(self):
        """実際のhttpx.Responseで404を返した場合（raise_for_status()が実際に例外を送出する
        経路）でも、リトライされずFalseを返すこと（Issue #130でのリトライ導入後の回帰防止）。"""
        request = httpx.Request("GET", "https://api.github.com")
        resp_404 = httpx.Response(404, request=request)
        mock_client = _mock_httpx_client(get_return=resp_404)
        with patch("httpx.Client", return_value=mock_client):
            assert has_ci_workflows(GitHubRepo("owner", "repo", "token")) is False
        mock_client.get.assert_called_once()

    def test_retries_on_transient_error_then_succeeds(self):
        """502等の一時的なエラーはリトライされ、最終的に成功すること（Issue #130）。"""
        request = httpx.Request("GET", "https://api.github.com")
        transient = httpx.Response(502, request=request)
        success = _mock_response([{"name": "ci.yml"}], status_code=200)
        mock_client = _mock_httpx_client()
        mock_client.get = MagicMock(side_effect=[transient, success])
        with patch("httpx.Client", return_value=mock_client), \
             patch("app.core.net.retry.time.sleep"):
            assert has_ci_workflows(GitHubRepo("owner", "repo", "token")) is True
        assert mock_client.get.call_count == 2


class TestListOpenDependabotAlerts:
    def test_returns_alert_list(self):
        alerts = [{"dependency": {"package": {"name": "requests"}}}]
        mock_client = _mock_httpx_client(get_return=_mock_response(alerts))
        with patch("httpx.Client", return_value=mock_client):
            result = list_open_dependabot_alerts(GitHubRepo("owner", "repo", "token"))
        assert result == alerts
        call = mock_client.get.call_args
        assert call.args[0].endswith("/dependabot/alerts")
        assert call.kwargs["params"]["state"] == "open"

    def test_raises_on_http_error(self):
        resp = MagicMock()
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "403", request=MagicMock(), response=MagicMock(),
        )
        mock_client = _mock_httpx_client(get_return=resp)
        import pytest
        with patch("httpx.Client", return_value=mock_client):
            with pytest.raises(httpx.HTTPStatusError):
                list_open_dependabot_alerts(GitHubRepo("owner", "repo", "token"))
