"""CODESCAN の Issue の自動クローズ（`close_resolved_repo_issues`）と、その前提となる
「失敗したツールの検知を、解決済みにしない」仕組みのテスト。"""
import os
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")

import httpx  # noqa: E402

from app.codescan.crawler import (  # noqa: E402
    ScanRecords,
    _run_codescan_body,
    failed_tools_of,
    scan_repo,
)
from app.codescan.issue_management import close_resolved_repo_issues  # noqa: E402
from app.codescan.models import CodeFinding  # noqa: E402
from app.codescan.repository import CodeFindingRepository  # noqa: E402
from app.codescan.user_scan import run_codescan_for_user  # noqa: E402
from app.core.crawler_runner import CrawlCounters  # noqa: E402
from app.finding_exceptions.models import FindingException  # noqa: E402
from tests.codescan.support import make_finding  # noqa: E402

_REPO = "app.core.github.repo.GitHubRepo"
_NOW = datetime.now(UTC)
_FULL = "baby-feelings/baby_grow"


def _record(rule: str = "rule.x", tool: str = "semgrep", repo: str = "owner/repo") -> dict:
    return {
        "repo_full_name": repo, "file_path": "a.py", "line_start": 1, "line_end": 1,
        "rule_id": rule, "message": "m", "severity": "ERROR", "cwe_ids": [],
        "owasp_categories": [], "code_snippet": "x", "cvss_score": None, "cvss_vector": None,
        "tool": tool, "detected_at": _NOW,
    }


class TestCloseResolvedRepoIssues:
    def test_closes_the_open_issue_when_nothing_needs_action(self, db_session):
        make_finding(db_session, resolved_at=_NOW)  # 解決済みのみ
        with patch(f"{_REPO}.find_open_issue", autospec=True, return_value=7), \
             patch(f"{_REPO}.add_issue_comment", autospec=True) as comment, \
             patch(f"{_REPO}.close_issue", autospec=True) as close:
            close_resolved_repo_issues(db_session, {_FULL})
        assert comment.call_args[0][1] == 7
        assert close.call_args[0][1] == 7

    def test_closes_when_there_are_no_findings_at_all(self, db_session):
        with patch(f"{_REPO}.find_open_issue", autospec=True, return_value=3), \
             patch(f"{_REPO}.add_issue_comment", autospec=True), \
             patch(f"{_REPO}.close_issue", autospec=True) as close:
            close_resolved_repo_issues(db_session, {_FULL})
        close.assert_called_once()

    def test_does_not_close_while_unresolved_findings_remain(self, db_session):
        make_finding(db_session, resolved_at=None)
        with patch(f"{_REPO}.find_open_issue", autospec=True) as find, \
             patch(f"{_REPO}.close_issue", autospec=True) as close:
            close_resolved_repo_issues(db_session, {_FULL})
        find.assert_not_called()
        close.assert_not_called()

    def test_excepted_findings_do_not_count_as_remaining(self, db_session):
        finding = make_finding(db_session, resolved_at=None)
        db_session.add(FindingException(
            kind="code", repo_full_name=_FULL,
            finding_key=f"{finding.file_path}|{finding.rule_id}", status="not_affected",
            reason="意図的", approver="owner", expires_at=_NOW + timedelta(days=5),
        ))
        db_session.commit()
        with patch(f"{_REPO}.find_open_issue", autospec=True, return_value=9), \
             patch(f"{_REPO}.add_issue_comment", autospec=True), \
             patch(f"{_REPO}.close_issue", autospec=True) as close:
            close_resolved_repo_issues(db_session, {_FULL})
        close.assert_called_once()

    def test_only_the_given_repos_are_checked(self, db_session):
        make_finding(db_session, repo_full_name="baby-feelings/other", resolved_at=None)
        with patch(f"{_REPO}.find_open_issue", autospec=True, return_value=None) as find:
            close_resolved_repo_issues(db_session, {_FULL})
        assert [c[0][0].full_name for c in find.call_args_list] == [_FULL]

    def test_does_nothing_without_an_open_issue(self, db_session):
        with patch(f"{_REPO}.find_open_issue", autospec=True, return_value=None), \
             patch(f"{_REPO}.close_issue", autospec=True) as close:
            close_resolved_repo_issues(db_session, {_FULL})
        close.assert_not_called()

    def test_empty_candidates_do_not_call_github(self, db_session):
        with patch(f"{_REPO}.find_open_issue", autospec=True) as find:
            close_resolved_repo_issues(db_session, set())
        find.assert_not_called()

    def test_http_error_is_swallowed_per_repo(self, db_session):
        error = httpx.HTTPStatusError("403", request=MagicMock(), response=MagicMock())
        with patch(f"{_REPO}.find_open_issue", autospec=True, side_effect=error):
            close_resolved_repo_issues(db_session, {_FULL, "baby-feelings/b"})  # 送出しない

    def test_uses_the_given_token(self, db_session):
        with patch(f"{_REPO}.find_open_issue", autospec=True, return_value=None), \
             patch("app.codescan.issue_management.GitHubRepo.from_full_name") as factory:
            factory.return_value.find_open_issue.return_value = None
            close_resolved_repo_issues(db_session, {_FULL}, token="gho_user")
        assert factory.call_args[0][1] == "gho_user"


class TestFailedToolsAreNotResolved:
    def test_finding_of_a_failed_tool_stays_unresolved(self, db_session):
        make_finding(db_session, repo_full_name="owner/repo", tool="zizmor", rule_id="zizmor:a")
        make_finding(db_session, repo_full_name="owner/repo", tool="semgrep", rule_id="sg.a")
        result = CodeFindingRepository(db_session).sync(
            "owner/repo", [], failed_tools=frozenset({"zizmor"}),
        )
        assert result.resolved == 1  # semgrep のものだけ
        unresolved = db_session.query(CodeFinding).filter(CodeFinding.resolved_at.is_(None))
        open_rules = {f.rule_id for f in unresolved}
        assert open_rules == {"zizmor:a"}

    def test_without_failures_everything_not_detected_is_resolved(self, db_session):
        make_finding(db_session, repo_full_name="owner/repo", tool="zizmor", rule_id="zizmor:a")
        result = CodeFindingRepository(db_session).sync("owner/repo", [])
        assert result.resolved == 1


class TestScanRepoFailedTools:
    def test_records_the_names_of_failed_scanners(self):
        ok, bad = MagicMock(), MagicMock()
        ok.name, bad.name = "semgrep", "zizmor"
        ok.scan.return_value = [_record()]
        bad.scan.side_effect = OSError("boom")
        with patch("app.codescan.crawler.GitHubRepo") as repo, \
             patch("app.codescan.crawler.RepoArchive") as archive:
            repo.from_full_name.return_value.tarball.return_value = b""
            archive.return_value.__enter__.return_value = "/tmp/x"
            records = scan_repo("owner/repo", "main", "t", scanners=[ok, bad])
        assert len(records) == 1
        assert failed_tools_of(records) == frozenset({"zizmor"})

    def test_plain_lists_have_no_failed_tools(self):
        assert failed_tools_of([]) == frozenset()
        assert failed_tools_of(ScanRecords()) == frozenset()


class TestRunBodyClosesIssues:
    def _run(self, db_session, records, repos=None):
        repos = repos or [{"full_name": "owner/repo", "default_branch": "main"}]
        with patch("app.codescan.crawler.list_target_repos", return_value=repos), \
             patch("app.codescan.crawler.scan_repo", return_value=records), \
             patch("app.codescan.crawler.file_github_issues"), \
             patch("app.codescan.crawler.close_resolved_repo_issues") as close:
            _run_codescan_body(db_session, CrawlCounters())
        return close

    def test_fully_scanned_repos_are_candidates(self, db_session):
        close = self._run(db_session, [_record()])
        assert close.call_args[0][1] == {"owner/repo"}

    def test_repo_with_a_failed_tool_is_not_a_candidate(self, db_session):
        records = ScanRecords([_record()])
        records.failed_tools = frozenset({"gitleaks"})
        close = self._run(db_session, records)
        assert close.call_args[0][1] == set()

    def test_repo_that_failed_to_scan_is_not_a_candidate(self, db_session):
        repos = [{"full_name": "owner/repo", "default_branch": "main"}]
        with patch("app.codescan.crawler.list_target_repos", return_value=repos), \
             patch("app.codescan.crawler.scan_repo", side_effect=httpx.ConnectError("x")), \
             patch("app.codescan.crawler.file_github_issues"), \
             patch("app.codescan.crawler.close_resolved_repo_issues") as close:
            _run_codescan_body(db_session, CrawlCounters())
        assert close.call_args[0][1] == set()

    def test_failed_tool_keeps_its_previous_findings(self, db_session):
        make_finding(db_session, repo_full_name="owner/repo", tool="zizmor", rule_id="zizmor:a")
        records = ScanRecords()
        records.failed_tools = frozenset({"zizmor"})
        self._run(db_session, records)
        assert db_session.query(CodeFinding).filter(CodeFinding.resolved_at.is_(None)).count() == 1

    def test_close_failure_does_not_raise(self, db_session):
        repos = [{"full_name": "owner/repo", "default_branch": "main"}]
        with patch("app.codescan.crawler.list_target_repos", return_value=repos), \
             patch("app.codescan.crawler.scan_repo", return_value=[]), \
             patch("app.codescan.crawler.file_github_issues"), \
             patch("app.codescan.crawler.close_resolved_repo_issues",
                   side_effect=RuntimeError("x")):
            _run_codescan_body(db_session, CrawlCounters())  # 送出しない


class TestUserScanClosesIssues:
    def _run(self, db_session, records, close_side_effect=None):
        repos = [{"full_name": "octocat/repo", "default_branch": "main"}]
        with patch("app.codescan.user_scan.list_target_repos", return_value=repos), \
             patch("app.codescan.user_scan.scan_repo", return_value=records), \
             patch("app.codescan.user_scan.SessionLocal", return_value=db_session), \
             patch("app.codescan.user_scan.get_webhook_for_user",
                   return_value="https://hooks.slack.com/x"), \
             patch("app.codescan.user_scan.notify_code_findings"), \
             patch("app.codescan.user_scan.file_github_issues"), \
             patch("app.codescan.user_scan.close_resolved_repo_issues",
                   side_effect=close_side_effect) as close:
            run_codescan_for_user("octocat", "gho_token")
        return close

    def test_closes_with_the_users_own_token(self, db_session):
        close = self._run(db_session, [_record(repo="octocat/repo")])
        assert close.call_args[0][1] == {"octocat/repo"}
        assert close.call_args[0][2] == "gho_token"

    def test_failed_tool_repo_is_not_a_candidate(self, db_session):
        records = ScanRecords([_record(repo="octocat/repo")])
        records.failed_tools = frozenset({"zizmor"})
        close = self._run(db_session, records)
        assert close.call_args[0][1] == set()

    def test_close_failure_does_not_raise(self, db_session):
        self._run(db_session, [], close_side_effect=RuntimeError("x"))
