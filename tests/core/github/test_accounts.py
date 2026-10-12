"""app.core.github.accounts（所有リポジトリの一覧）のテスト。外部HTTP通信はすべてモックする。"""
import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")


from app.core.github.accounts import list_target_repos  # noqa: E402


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


class TestListTargetRepos:
    def test_excludes_fork_and_archived(self):
        repos = [
            {"full_name": "u/a", "fork": False, "archived": False},
            {"full_name": "u/fork", "fork": True, "archived": False},
            {"full_name": "u/old", "fork": False, "archived": True},
        ]
        mock_client = _mock_httpx_client(get_return=_mock_response(repos))
        with patch("httpx.Client", return_value=mock_client):
            result = list_target_repos("u", "token")
        assert [r["full_name"] for r in result] == ["u/a"]

    def test_paginates_until_short_page(self):
        page1 = [{"full_name": f"u/r{i}", "fork": False, "archived": False} for i in range(100)]
        page2 = [{"full_name": "u/last", "fork": False, "archived": False}]
        responses = [_mock_response(page1), _mock_response(page2)]
        mock_client = _mock_httpx_client()
        mock_client.get = MagicMock(side_effect=responses)
        with patch("httpx.Client", return_value=mock_client):
            result = list_target_repos("u", "token")
        assert len(result) == 101
        assert mock_client.get.call_count == 2

    def test_uses_authenticated_user_repos_endpoint(self):
        """プライベートリポジトリも取得できるよう /user/repos (affiliation=owner) を使う。"""
        repos = [{"full_name": "u/private", "fork": False, "archived": False, "private": True}]
        mock_client = _mock_httpx_client(get_return=_mock_response(repos))
        with patch("httpx.Client", return_value=mock_client):
            list_target_repos("u", "token")
        call = mock_client.get.call_args
        assert call.args[0].endswith("/user/repos")
        assert call.kwargs["params"]["affiliation"] == "owner"
