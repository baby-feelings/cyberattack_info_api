"""app.depscan.source_files（到達可能性解析用のソース収集）のテスト。"""
import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

import httpx  # noqa: E402

from app.core.github.repo import GitHubRepo  # noqa: E402
from app.depscan.source_files import collect_source_files  # noqa: E402


class TestCollectSourceFiles:
    def test_filters_by_extension_and_fetches_content(self):
        paths = ["app/main.py", "README.md", "app/utils.py"]
        with patch("app.core.github.repo.GitHubRepo.tree", return_value=paths), \
             patch(
                 "app.core.github.repo.GitHubRepo.file_content",
                 side_effect=lambda path: f"# {path}",
             ):
            files = collect_source_files(GitHubRepo("owner", "repo", "token"), "main", (".py",))

        assert set(files.keys()) == {"app/main.py", "app/utils.py"}
        assert files["app/main.py"] == "# app/main.py"

    def test_excludes_vendored_directories(self):
        paths = ["app/main.py", "node_modules/pkg/index.js"]
        with patch("app.core.github.repo.GitHubRepo.tree", return_value=paths), \
             patch("app.core.github.repo.GitHubRepo.file_content", return_value="content"):
            files = collect_source_files(
                GitHubRepo("owner", "repo", "token"), "main", (".py", ".js"),
            )

        assert list(files.keys()) == ["app/main.py"]

    def test_fetch_failure_for_one_file_does_not_fail_others(self):
        paths = ["a.py", "b.py"]
        with patch("app.core.github.repo.GitHubRepo.tree", return_value=paths), \
             patch(
                 "app.core.github.repo.GitHubRepo.file_content",
                 side_effect=[
                     httpx.HTTPStatusError("404", request=MagicMock(), response=MagicMock()),
                     "content-b",
                 ],
             ):
            files = collect_source_files(GitHubRepo("owner", "repo", "token"), "main", (".py",))

        assert files == {"b.py": "content-b"}

    def test_oversized_file_is_skipped(self):
        with patch("app.core.github.repo.GitHubRepo.tree", return_value=["big.py"]), \
             patch("app.core.github.repo.GitHubRepo.file_content", return_value="x" * 400_000):
            files = collect_source_files(GitHubRepo("owner", "repo", "token"), "main", (".py",))

        assert files == {}
