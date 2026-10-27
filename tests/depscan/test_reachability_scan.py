"""app.depscan.reachability_scan（到達可能性の付与）のテスト。"""
import os
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

import httpx  # noqa: E402

TEST_API_KEY = "test-api-key-for-pytest"
HEADERS = {"X-API-KEY": TEST_API_KEY}
_NOW = datetime.now(UTC)
_REPO = "app.core.github.repo.GitHubRepo"

from app.depscan.reachability_scan import apply_reachability  # noqa: E402


class TestApplyReachability:
    def test_updates_records_using_fetched_source(self):
        records = [
            {"repo_full_name": "u/r", "ecosystem": "PyPI", "package_name": "requests"},
        ]
        repos = [{"full_name": "u/r", "default_branch": "main"}]
        with patch("app.depscan.reachability_scan.list_target_repos", return_value=repos), \
             patch(
                 "app.depscan.reachability_scan.collect_source_files",
                 return_value={"app/main.py": "import requests\n"},
             ):
            apply_reachability(records, "token")

        assert records[0]["reachability"] == "reachable"

    def test_shares_fetched_source_across_findings_in_same_repo_and_ecosystem(self):
        records = [
            {"repo_full_name": "u/r", "ecosystem": "PyPI", "package_name": "requests"},
            {"repo_full_name": "u/r", "ecosystem": "PyPI", "package_name": "flask"},
        ]
        repos = [{"full_name": "u/r", "default_branch": "main"}]
        with patch("app.depscan.reachability_scan.list_target_repos", return_value=repos), \
             patch(
                 "app.depscan.reachability_scan.collect_source_files",
                 return_value={"app/main.py": "import requests\n"},
             ) as mock_get_source:
            apply_reachability(records, "token")

        mock_get_source.assert_called_once()
        assert records[0]["reachability"] == "reachable"
        assert records[1]["reachability"] == "unreachable"

    def test_source_fetch_failure_leaves_reachability_unchanged(self):
        records = [
            {
                "repo_full_name": "u/r", "ecosystem": "PyPI", "package_name": "requests",
                "reachability": "unknown",
            },
        ]
        repos = [{"full_name": "u/r", "default_branch": "main"}]
        http_error = httpx.HTTPStatusError("500", request=MagicMock(), response=MagicMock())
        with patch("app.depscan.reachability_scan.list_target_repos", return_value=repos), \
             patch("app.depscan.reachability_scan.collect_source_files", side_effect=http_error):
            apply_reachability(records, "token")

        assert records[0]["reachability"] == "unknown"

    def test_empty_records_does_not_call_github(self):
        with patch("app.depscan.reachability_scan.list_target_repos") as mock_list:
            apply_reachability([], "token")
        mock_list.assert_not_called()
