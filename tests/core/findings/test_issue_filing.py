"""app.core.findings.issue_filing.IssueReporter（Issue 起票・自動クローズの共通の手順）のテスト。

ドメイン固有の差分（タイトル・本文・未解決の数え方）だけを持つ最小のサブクラスで、
共通の手順（トークンの既定値・例外の握りつぶし・クローズの判定）を確認する。
"""
import os
from typing import Any
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

import httpx  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.core.findings.issue_filing import IssueReporter  # noqa: E402

_FACTORY = "app.core.github.repo.GitHubRepo.from_full_name"


class _Reporter(IssueReporter):
    source = "TEST"
    issue_title = "テストの Issue"
    resolved_subject = "テストの指摘"

    def __init__(self, unresolved: dict[str, int] | None = None) -> None:
        self._unresolved = unresolved or {}

    def format_body(self, findings: list[dict[str, Any]], timestamp: str) -> str:
        return f"{len(findings)}件 / {timestamp}"

    def unresolved_count(self, db: Any, full_name: str) -> int:
        return self._unresolved.get(full_name, 0)


def _repo_mock(find_result: int | None = 5) -> MagicMock:
    repo = MagicMock()
    repo.find_open_issue.return_value = find_result
    return repo


class TestFileIssues:
    def test_nothing_to_file_does_not_touch_github(self):
        with patch(_FACTORY) as factory:
            _Reporter().file_issues([])
        factory.assert_not_called()

    def test_files_per_repo_and_uses_the_default_token(self):
        repo = _repo_mock(find_result=None)
        repo.create_issue.return_value = {"number": 1}
        snapshots = [{"repo_full_name": "o/a"}, {"repo_full_name": "o/a"}]
        with patch(_FACTORY, return_value=repo) as factory:
            _Reporter().file_issues(snapshots)
        assert factory.call_args[0] == ("o/a", settings.GITHUB_TOKEN)
        title, body = repo.create_issue.call_args[0]
        assert title == "テストの Issue"
        assert body.startswith("2件 / ")

    def test_uses_the_given_token(self):
        repo = _repo_mock(find_result=5)
        with patch(_FACTORY, return_value=repo) as factory:
            _Reporter().file_issues([{"repo_full_name": "o/a"}], token="gho_user")
        assert factory.call_args[0][1] == "gho_user"
        repo.add_issue_comment.assert_called_once()  # 既存の Issue には追記する


class TestCloseResolved:
    def test_no_candidates_does_not_touch_github(self):
        with patch(_FACTORY) as factory:
            _Reporter().close_resolved(MagicMock(), set())
        factory.assert_not_called()

    def test_repo_with_unresolved_findings_is_skipped(self):
        with patch(_FACTORY) as factory:
            _Reporter({"o/a": 2}).close_resolved(MagicMock(), {"o/a"})
        factory.assert_not_called()

    def test_closes_when_nothing_is_left(self):
        repo = _repo_mock(find_result=7)
        with patch(_FACTORY, return_value=repo):
            _Reporter().close_resolved(MagicMock(), {"o/a"})
        comment = repo.add_issue_comment.call_args[0][1]
        assert "対応が必要なテストの指摘（受容などの例外を除く）が0件" in comment
        repo.close_issue.assert_called_once_with(7)

    def test_no_open_issue_is_a_noop(self):
        repo = _repo_mock(find_result=None)
        with patch(_FACTORY, return_value=repo):
            _Reporter().close_resolved(MagicMock(), {"o/a"})
        repo.close_issue.assert_not_called()

    def test_http_error_is_swallowed_per_repo(self):
        repo = _repo_mock()
        repo.find_open_issue.side_effect = httpx.ConnectError("x")
        with patch(_FACTORY, return_value=repo):
            _Reporter().close_resolved(MagicMock(), {"o/a", "o/b"})  # 送出しない
        assert repo.find_open_issue.call_count == 2  # 1件の失敗で、残りを止めない
