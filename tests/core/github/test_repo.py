"""app.core.github.repo（GitHubRepo。1リポジトリへの共通操作）のテスト。外部HTTP通信はすべてモックする。"""
import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

import httpx  # noqa: E402
import pytest  # noqa: E402

from app.core.github.repo import GitHubRepo  # noqa: E402


def _mock_httpx_client(get_return=None, post_return=None, patch_return=None) -> MagicMock:
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    if get_return is not None:
        mock_client.get = MagicMock(return_value=get_return)
    if post_return is not None:
        mock_client.post = MagicMock(return_value=post_return)
    if patch_return is not None:
        mock_client.patch = MagicMock(return_value=patch_return)
    return mock_client


def _mock_response(json_data) -> MagicMock:
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = json_data
    return resp


def _mock_client(get_return) -> MagicMock:
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.get = MagicMock(return_value=get_return)
    return mock_client


class TestExists:
    def test_returns_true_when_repo_found(self):
        mock_client = _mock_httpx_client(get_return=_mock_response({"full_name": "u/r"}))
        with patch("httpx.Client", return_value=mock_client):
            assert GitHubRepo("u", "r", "token").exists() is True

    def test_returns_false_on_404(self):
        resp = MagicMock()
        resp.status_code = 404
        resp.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError("404", request=MagicMock(), response=resp),
        )
        mock_client = _mock_httpx_client(get_return=resp)
        with patch("httpx.Client", return_value=mock_client):
            assert GitHubRepo("u", "deleted-repo", "token").exists() is False

    def test_returns_none_on_other_http_status_error(self):
        resp = MagicMock()
        resp.status_code = 401
        resp.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError("401", request=MagicMock(), response=resp),
        )
        mock_client = _mock_httpx_client(get_return=resp)
        with patch("httpx.Client", return_value=mock_client):
            assert GitHubRepo("u", "r", "token").exists() is None

    def test_returns_none_on_transport_error(self):
        mock_client = _mock_httpx_client()
        mock_client.get = MagicMock(side_effect=httpx.ConnectError("boom"))
        with patch("httpx.Client", return_value=mock_client):
            assert GitHubRepo("u", "r", "token").exists() is None


class TestTree:
    def test_returns_blob_paths_only(self):
        tree_data = {
            "tree": [
                {"path": "requirements.txt", "type": "blob"},
                {"path": "app", "type": "tree"},
            ],
            "truncated": False,
        }
        mock_client = _mock_httpx_client(get_return=_mock_response(tree_data))
        with patch("httpx.Client", return_value=mock_client):
            paths = GitHubRepo("owner", "repo", "token").tree("main")
        assert paths == ["requirements.txt"]


class TestFileContent:
    def test_decodes_base64_content(self):
        import base64
        encoded = base64.b64encode(b"fastapi==0.115.6\n").decode()
        mock_client = _mock_httpx_client(
            get_return=_mock_response({"content": encoded, "encoding": "base64"})
        )
        with patch("httpx.Client", return_value=mock_client):
            content = GitHubRepo("owner", "repo", "token").file_content("requirements.txt")
        assert content == "fastapi==0.115.6\n"

    def test_unsupported_encoding_raises(self):
        mock_client = _mock_httpx_client(
            get_return=_mock_response({"content": "x", "encoding": "utf-8"})
        )
        with patch("httpx.Client", return_value=mock_client):
            with pytest.raises(ValueError):
                GitHubRepo("owner", "repo", "token").file_content("path")


class TestFindOpenIssue:
    def test_returns_matching_issue_number(self):
        issues = [
            {"number": 5, "title": "別件のIssue"},
            {"number": 7, "title": "🚨 依存ライブラリの脆弱性が検出されました (DEPSCAN)"},
        ]
        mock_client = _mock_httpx_client(get_return=_mock_response(issues))
        with patch("httpx.Client", return_value=mock_client):
            result = GitHubRepo("owner", "repo", "token").find_open_issue(
                "🚨 依存ライブラリの脆弱性が検出されました (DEPSCAN)",
            )
        assert result == 7

    def test_returns_none_when_not_found(self):
        mock_client = _mock_httpx_client(get_return=_mock_response([]))
        with patch("httpx.Client", return_value=mock_client):
            result = GitHubRepo("owner", "repo", "token").find_open_issue("存在しないタイトル")
        assert result is None

    def test_ignores_pull_requests(self):
        """タイトルが一致してもPull Requestは除外する（issues APIはPRも含んで返すため）。"""
        issues = [{"number": 3, "title": "同じタイトル", "pull_request": {"url": "..."}}]
        mock_client = _mock_httpx_client(get_return=_mock_response(issues))
        with patch("httpx.Client", return_value=mock_client):
            result = GitHubRepo("owner", "repo", "token").find_open_issue("同じタイトル")
        assert result is None


class TestCreateAndCommentAndClose:
    def test_create_issue_posts_title_and_body(self):
        mock_client = _mock_httpx_client(post_return=_mock_response({"number": 42}))
        with patch("httpx.Client", return_value=mock_client):
            result = GitHubRepo("owner", "repo", "token").create_issue("タイトル", "本文")
        assert result == {"number": 42}
        call = mock_client.post.call_args
        assert call.kwargs["json"] == {"title": "タイトル", "body": "本文"}

    def test_add_issue_comment_posts_body(self):
        mock_client = _mock_httpx_client(post_return=_mock_response({"id": 1}))
        with patch("httpx.Client", return_value=mock_client):
            result = GitHubRepo("owner", "repo", "token").add_issue_comment(42, "追記内容")
        assert result == {"id": 1}
        call = mock_client.post.call_args
        assert call.args[0].endswith("/issues/42/comments")
        assert call.kwargs["json"] == {"body": "追記内容"}

    def test_close_issue_patches_state_closed(self):
        resp = _mock_response({"number": 42, "state": "closed"})
        mock_client = _mock_httpx_client(patch_return=resp)
        with patch("httpx.Client", return_value=mock_client):
            result = GitHubRepo("owner", "repo", "token").close_issue(42)
        assert result == {"number": 42, "state": "closed"}
        call = mock_client.patch.call_args
        assert call.args[0].endswith("/issues/42")
        assert call.kwargs["json"] == {"state": "closed"}


# ──────────────────────────────────────────────────────────────
# app.depscan.crawler
# ──────────────────────────────────────────────────────────────


class TestTarball:
    def test_returns_response_content(self):
        mock_response = MagicMock()
        mock_response.content = b"fake-tarball-bytes"
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client", return_value=_mock_client(mock_response)):
            result = GitHubRepo("owner", "repo", "token123").tarball()

        assert result == b"fake-tarball-bytes"

    def test_uses_follow_redirects_and_default_branch(self):
        mock_response = MagicMock()
        mock_response.content = b"x"
        mock_response.raise_for_status = MagicMock()
        captured = {}

        def _client_factory(*args, **kwargs):
            captured.update(kwargs)
            return _mock_client(mock_response)

        with patch("httpx.Client", side_effect=_client_factory):
            GitHubRepo("owner", "repo", "token123").tarball()

        assert captured.get("follow_redirects") is True

    def test_custom_branch_is_used_in_url(self):
        mock_response = MagicMock()
        mock_response.content = b"x"
        mock_response.raise_for_status = MagicMock()
        mock_client = _mock_client(mock_response)

        with patch("httpx.Client", return_value=mock_client):
            GitHubRepo("owner", "repo", "token123").tarball("v1.0.0")

        called_url = mock_client.get.call_args[0][0]
        assert called_url.endswith("/repos/owner/repo/tarball/v1.0.0")


class TestIdentity:
    def test_from_full_name_splits_owner_and_name(self):
        repo = GitHubRepo.from_full_name("octo/cat", "tok")
        assert (repo.owner, repo.name, repo.full_name) == ("octo", "cat", "octo/cat")

    def test_token_is_not_shown_in_repr(self):
        assert "secret-token" not in repr(GitHubRepo("o", "r", "secret-token"))

    def test_path_builds_repo_scoped_api_paths(self):
        repo = GitHubRepo("o", "r", "t")
        assert repo.path() == "/repos/o/r"
        assert repo.path("/pulls") == "/repos/o/r/pulls"
