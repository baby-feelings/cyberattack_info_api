"""app.depscan.manifests（ロックファイルの収集とパース）のテスト。"""
import os
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

import httpx  # noqa: E402

from app.core.github.repo import GitHubRepo  # noqa: E402

TEST_API_KEY = "test-api-key-for-pytest"
HEADERS = {"X-API-KEY": TEST_API_KEY}
_NOW = datetime.now(UTC)
_REPO = "app.core.github.repo.GitHubRepo"

from app.depscan.manifests import collect_dependencies, discover_manifests  # noqa: E402


class TestDiscoverManifests:
    def test_filters_by_known_filenames(self):
        with patch(
            f"{_REPO}.tree",
            return_value=["requirements.txt", "app/main.py", "dashboard/package-lock.json"],
        ):
            manifests = discover_manifests(GitHubRepo("owner", "repo", "token"), "main")
        assert manifests == ["requirements.txt", "dashboard/package-lock.json"]

    def test_http_error_returns_empty(self):
        with patch(
            f"{_REPO}.tree",
            side_effect=httpx.HTTPStatusError("500", request=MagicMock(), response=MagicMock()),
        ):
            assert discover_manifests(GitHubRepo("owner", "repo", "token"), "main") == []


class TestCollectDependencies:
    def test_aggregates_across_repos(self):
        repos = [{"full_name": "u/repo1", "default_branch": "main"}]
        with patch("app.depscan.manifests.list_target_repos", return_value=repos), \
             patch("app.depscan.manifests.discover_manifests", return_value=["requirements.txt"]), \
             patch(f"{_REPO}.file_content", return_value="fastapi==0.115.6\n"):
            dep_to_repos, repos_scanned, repo_visibility = collect_dependencies("token")

        assert repos_scanned == 1
        assert dep_to_repos[("PyPI", "fastapi", "0.115.6")] == [("u/repo1", "requirements.txt")]
        assert repo_visibility == {"u/repo1": "public"}

    def test_fetch_failure_skips_file(self):
        repos = [{"full_name": "u/repo1", "default_branch": "main"}]
        with patch("app.depscan.manifests.list_target_repos", return_value=repos), \
             patch("app.depscan.manifests.discover_manifests", return_value=["requirements.txt"]), \
             patch(
                 f"{_REPO}.file_content",
                 side_effect=httpx.HTTPStatusError(
                     "404", request=MagicMock(), response=MagicMock()
                 ),
             ):
            dep_to_repos, repos_scanned, repo_visibility = collect_dependencies("token")
        assert dep_to_repos == {}
        assert repos_scanned == 1

    def test_repo_visibility_derived_from_private_field(self):
        """Issue #131: GitHub APIの"private"フィールドからrepo_visibilityを導出すること。"""
        repos = [
            {"full_name": "u/public-repo", "default_branch": "main", "private": False},
            {"full_name": "u/private-repo", "default_branch": "main", "private": True},
        ]
        with patch("app.depscan.manifests.list_target_repos", return_value=repos), \
             patch("app.depscan.manifests.discover_manifests", return_value=[]):
            _, _, repo_visibility = collect_dependencies("token")
        assert repo_visibility == {"u/public-repo": "public", "u/private-repo": "private"}
