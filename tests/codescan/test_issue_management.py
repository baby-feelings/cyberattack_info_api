"""app.codescan.issue_management（CODESCAN の GitHub Issue 自動起票）のテスト。"""
import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

import httpx  # noqa: E402

from app.codescan.issue_management import _file_github_issues  # noqa: E402


def _finding(**kwargs) -> dict:
    base = {
        "repo_full_name": "baby-feelings/baby_grow",
        "file_path": "app/main.py",
        "line_start": 10,
        "line_end": 12,
        "rule_id": "python.lang.security.audit.hardcoded-password",
        "message": "Hardcoded password detected",
        "severity": "ERROR",
        "cvss_score": 7.5,
    }
    base.update(kwargs)
    return base


class TestFileGithubIssues:
    # 実際の GitHub API 呼び出しは app.core.issue_filing に共通処理として切り出されて
    # いるため、モックはそちら側を対象にする（DEPSCAN 側テストと同じ方針）

    def test_does_nothing_when_no_new_findings(self):
        with patch("app.core.issue_filing.find_open_issue") as mock_find:
            _file_github_issues([])
        mock_find.assert_not_called()

    def test_creates_issue_when_none_open(self):
        with patch("app.core.issue_filing.find_open_issue", return_value=None), \
             patch("app.core.issue_filing.create_issue") as mock_create, \
             patch("app.core.issue_filing.add_issue_comment") as mock_comment:
            _file_github_issues([_finding()])
        mock_create.assert_called_once()
        args = mock_create.call_args[0]
        assert args[0] == "baby-feelings"
        assert args[1] == "baby_grow"
        assert "CODESCAN" in args[2]  # 固定タイトルにCODESCANを含む
        assert "hardcoded-password" in args[3]
        mock_comment.assert_not_called()

    def test_uses_codescan_specific_title_distinct_from_depscan(self):
        with patch(
            "app.core.issue_filing.find_open_issue", return_value=None,
        ) as mock_find, \
             patch("app.core.issue_filing.create_issue"), \
             patch("app.core.issue_filing.add_issue_comment"):
            _file_github_issues([_finding()])
        title = mock_find.call_args[0][2]
        assert "DEPSCAN" not in title
        assert "CODESCAN" in title

    def test_comments_on_existing_open_issue(self):
        with patch("app.core.issue_filing.find_open_issue", return_value=7), \
             patch("app.core.issue_filing.create_issue") as mock_create, \
             patch("app.core.issue_filing.add_issue_comment") as mock_comment:
            _file_github_issues([_finding()])
        mock_comment.assert_called_once()
        assert mock_comment.call_args[0][2] == 7
        mock_create.assert_not_called()

    def test_groups_by_repo(self):
        findings = [
            _finding(repo_full_name="u/a"),
            _finding(repo_full_name="u/b"),
        ]
        with patch("app.core.issue_filing.find_open_issue", return_value=None), \
             patch("app.core.issue_filing.create_issue") as mock_create, \
             patch("app.core.issue_filing.add_issue_comment"):
            _file_github_issues(findings)
        assert mock_create.call_count == 2

    def test_sorts_by_severity_then_file(self):
        findings = [
            _finding(file_path="b.py", severity="INFO"),
            _finding(file_path="a.py", severity="ERROR"),
        ]
        with patch("app.core.issue_filing.find_open_issue", return_value=None), \
             patch("app.core.issue_filing.create_issue") as mock_create, \
             patch("app.core.issue_filing.add_issue_comment"):
            _file_github_issues(findings)
        body = mock_create.call_args[0][3]
        assert body.index("a.py") < body.index("b.py")

    def test_http_error_does_not_raise(self):
        """権限不足等でIssue作成が失敗しても、CODESCAN全体を失敗させない。"""
        with patch(
            "app.core.issue_filing.find_open_issue",
            side_effect=httpx.HTTPStatusError("403", request=MagicMock(), response=MagicMock()),
        ):
            _file_github_issues([_finding()])  # 例外を送出しないことを確認
