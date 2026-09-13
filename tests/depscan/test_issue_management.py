"""app.depscan.issue_management（DEPSCAN の GitHub Issue 自動起票・自動クローズ）のテスト。

app.depscan.crawler から切り出したモジュール。元は tests/depscan/test_depscan.py の
TestFileGithubIssues・TestCloseResolvedRepoIssues としてテストされていたものを、
モジュール分割に合わせて移動した（アサーション内容は変更していない）。
"""
import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

import httpx  # noqa: E402

from app.depscan.issue_management import (  # noqa: E402
    _close_resolved_repo_issues,
    _file_github_issues,
)
from app.depscan.models import DependencyFinding  # noqa: E402

_NOW = datetime.now(timezone.utc)


def _make_finding(db_session, **kwargs) -> DependencyFinding:
    defaults = {
        "repo_full_name": "baby-feelings/baby_grow",
        "ecosystem": "PyPI",
        "package_name": "cryptography",
        "installed_version": "3.4.7",
        "osv_id": "GHSA-test-0001",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "summary": "Test vulnerability",
        "fixed_versions": ["3.4.8"],
        "manifest_path": "requirements.txt",
        "detected_at": _NOW,
        "resolved_at": None,
    }
    defaults.update(kwargs)
    record = DependencyFinding(**defaults)
    db_session.add(record)
    db_session.commit()
    return record


class TestFileGithubIssues:
    def _finding(self, **kwargs):
        base = {
            "repo_full_name": "baby-feelings/baby_grow",
            "package_name": "cryptography",
            "installed_version": "3.4.7",
            "severity": "HIGH",
            "fixed_versions": ["3.4.8"],
            "osv_id": "GHSA-001",
        }
        base.update(kwargs)
        return base

    def test_does_nothing_when_no_new_findings(self):
        with patch("app.depscan.issue_management.find_open_issue") as mock_find:
            _file_github_issues([])
        mock_find.assert_not_called()

    def test_creates_issue_when_none_open(self):
        with patch("app.depscan.issue_management.find_open_issue", return_value=None), \
             patch("app.depscan.issue_management.create_issue") as mock_create, \
             patch("app.depscan.issue_management.add_issue_comment") as mock_comment:
            _file_github_issues([self._finding()])
        mock_create.assert_called_once()
        args = mock_create.call_args[0]
        assert args[0] == "baby-feelings"
        assert args[1] == "baby_grow"
        assert "cryptography" in args[3]
        mock_comment.assert_not_called()

    def test_comments_on_existing_open_issue(self):
        with patch("app.depscan.issue_management.find_open_issue", return_value=7), \
             patch("app.depscan.issue_management.create_issue") as mock_create, \
             patch("app.depscan.issue_management.add_issue_comment") as mock_comment:
            _file_github_issues([self._finding()])
        mock_comment.assert_called_once()
        assert mock_comment.call_args[0][2] == 7
        mock_create.assert_not_called()

    def test_groups_by_repo(self):
        findings = [
            self._finding(repo_full_name="u/a", osv_id="GHSA-a"),
            self._finding(repo_full_name="u/b", osv_id="GHSA-b"),
        ]
        with patch("app.depscan.issue_management.find_open_issue", return_value=None), \
             patch("app.depscan.issue_management.create_issue") as mock_create, \
             patch("app.depscan.issue_management.add_issue_comment"):
            _file_github_issues(findings)
        assert mock_create.call_count == 2

    def test_http_error_does_not_raise(self):
        """権限不足等でIssue作成が失敗しても、DEPSCAN全体を失敗させない。"""
        with patch(
            "app.depscan.issue_management.find_open_issue",
            side_effect=httpx.HTTPStatusError("403", request=MagicMock(), response=MagicMock()),
        ):
            _file_github_issues([self._finding()])  # 例外を送出しないことを確認


class TestCloseResolvedRepoIssues:
    def test_closes_issue_when_no_unresolved_findings_remain(self, db_session):
        """候補リポジトリに未解決findingが0件なら、Open issueを見つけてクローズする。"""
        with patch("app.depscan.issue_management.find_open_issue", return_value=7), \
             patch("app.depscan.issue_management.add_issue_comment") as mock_comment, \
             patch("app.depscan.issue_management.close_issue") as mock_close:
            _close_resolved_repo_issues(db_session, {"baby-feelings/baby_grow"})

        mock_comment.assert_called_once()
        assert mock_comment.call_args[0][:3] == ("baby-feelings", "baby_grow", 7)
        mock_close.assert_called_once()
        assert mock_close.call_args[0][:3] == ("baby-feelings", "baby_grow", 7)

    def test_does_not_close_when_unresolved_findings_remain(self, db_session):
        """候補リポジトリに未解決findingが1件でも残っていればクローズしない。"""
        _make_finding(db_session, resolved_at=None)  # 未解決のまま残っている

        with patch("app.depscan.issue_management.find_open_issue") as mock_find, \
             patch("app.depscan.issue_management.close_issue") as mock_close:
            _close_resolved_repo_issues(db_session, {"baby-feelings/baby_grow"})

        mock_find.assert_not_called()
        mock_close.assert_not_called()

    def test_does_nothing_when_no_open_issue_exists(self, db_session):
        with patch("app.depscan.issue_management.find_open_issue", return_value=None), \
             patch("app.depscan.issue_management.close_issue") as mock_close:
            _close_resolved_repo_issues(db_session, {"baby-feelings/baby_grow"})

        mock_close.assert_not_called()

    def test_empty_candidate_repos_does_not_query_github(self, db_session):
        with patch("app.depscan.issue_management.find_open_issue") as mock_find:
            _close_resolved_repo_issues(db_session, set())

        mock_find.assert_not_called()

    def test_http_error_does_not_raise(self, db_session):
        """権限不足等でクローズが失敗しても、DEPSCAN全体を失敗させない。"""
        with patch(
            "app.depscan.issue_management.find_open_issue",
            side_effect=httpx.HTTPStatusError("403", request=MagicMock(), response=MagicMock()),
        ):
            _close_resolved_repo_issues(db_session, {"baby-feelings/baby_grow"})  # 例外を送出しない
