"""app.codescan.github_client（tarball取得）のテスト。外部HTTP通信はすべてモックする。"""
import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.codescan.github_client import download_repo_tarball  # noqa: E402


def _mock_client(get_return) -> MagicMock:
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.get = MagicMock(return_value=get_return)
    return mock_client


class TestDownloadRepoTarball:
    def test_returns_response_content(self):
        mock_response = MagicMock()
        mock_response.content = b"fake-tarball-bytes"
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client", return_value=_mock_client(mock_response)):
            result = download_repo_tarball("owner", "repo", "token123")

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
            download_repo_tarball("owner", "repo", "token123")

        assert captured.get("follow_redirects") is True

    def test_custom_branch_is_used_in_url(self):
        mock_response = MagicMock()
        mock_response.content = b"x"
        mock_response.raise_for_status = MagicMock()
        mock_client = _mock_client(mock_response)

        with patch("httpx.Client", return_value=mock_client):
            download_repo_tarball("owner", "repo", "token123", branch="v1.0.0")

        called_url = mock_client.get.call_args[0][0]
        assert called_url.endswith("/repos/owner/repo/tarball/v1.0.0")
