"""app.codescan.user_scan.run_codescan_for_user（Issue #227）のテスト。"""
from datetime import datetime, timezone
from unittest.mock import patch

from app.codescan.models import CodeFinding
from app.codescan.user_scan import run_codescan_for_user

_NOW = datetime.now(timezone.utc)


def _finding(**kwargs):
    base = {
        "repo_full_name": "octocat/repo",
        "file_path": "app.py",
        "line_start": 1,
        "line_end": 1,
        "rule_id": "python.lang.security.audit.hardcoded-password",
        "message": "hardcoded password",
        "severity": "ERROR",
        "cwe_ids": ["CWE-798"],
        "owasp_categories": [],
        "code_snippet": "password = 'x'",
        "cvss_score": 7.7,
        "cvss_vector": "AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "tool": "semgrep",
        "detected_at": _NOW,
    }
    base.update(kwargs)
    return base


class TestRunCodescanForUser:
    def test_success_path_inserts_findings(self, db_session):
        repos = [{"full_name": "octocat/repo", "default_branch": "main"}]
        with patch("app.codescan.user_scan.list_target_repos", return_value=repos), \
             patch("app.codescan.user_scan._scan_repo", return_value=[_finding()]), \
             patch("app.codescan.user_scan.SessionLocal", return_value=db_session):
            run_codescan_for_user("octocat", "gho_token")

        count = db_session.query(CodeFinding).filter_by(repo_full_name="octocat/repo").count()
        assert count == 1

    def test_skips_repo_on_scan_failure_and_continues(self, db_session):
        import httpx

        repos = [
            {"full_name": "octocat/broken", "default_branch": "main"},
            {"full_name": "octocat/ok", "default_branch": "main"},
        ]

        def _scan_side_effect(full_name, branch, token):
            if full_name == "octocat/broken":
                raise httpx.HTTPError("boom")
            return [_finding(repo_full_name=full_name)]

        with patch("app.codescan.user_scan.list_target_repos", return_value=repos), \
             patch("app.codescan.user_scan._scan_repo", side_effect=_scan_side_effect), \
             patch("app.codescan.user_scan.SessionLocal", return_value=db_session):
            run_codescan_for_user("octocat", "gho_token")

        count = db_session.query(CodeFinding).filter_by(repo_full_name="octocat/ok").count()
        assert count == 1
        broken_count = (
            db_session.query(CodeFinding).filter_by(repo_full_name="octocat/broken").count()
        )
        assert broken_count == 0

    def test_notifies_and_files_issues_when_webhook_registered(self, db_session):
        from app.auth.account_store import set_slack_webhook, upsert_user_token

        upsert_user_token(db_session, "octocat", "gho_token")
        set_slack_webhook(db_session, "octocat", "https://hooks.slack.com/services/octocat")

        repos = [{"full_name": "octocat/repo", "default_branch": "main"}]
        with patch("app.codescan.user_scan.list_target_repos", return_value=repos), \
             patch("app.codescan.user_scan._scan_repo", return_value=[_finding()]), \
             patch("app.codescan.user_scan.SessionLocal", return_value=db_session), \
             patch("app.codescan.user_scan.notify_success") as mock_notify, \
             patch("app.codescan.user_scan._file_github_issues") as mock_file_issues:
            run_codescan_for_user("octocat", "gho_token")

        mock_notify.assert_called_once()
        assert mock_notify.call_args.kwargs["recipients"] == [
            "https://hooks.slack.com/services/octocat",
        ]
        mock_file_issues.assert_called_once()
        assert mock_file_issues.call_args[0][1] == "gho_token"

    def test_no_notification_when_webhook_not_registered(self, db_session):
        repos = [{"full_name": "octocat/repo", "default_branch": "main"}]
        with patch("app.codescan.user_scan.list_target_repos", return_value=repos), \
             patch("app.codescan.user_scan._scan_repo", return_value=[_finding()]), \
             patch("app.codescan.user_scan.SessionLocal", return_value=db_session), \
             patch("app.codescan.user_scan.notify_success") as mock_notify, \
             patch("app.codescan.user_scan._file_github_issues") as mock_file_issues:
            run_codescan_for_user("octocat", "gho_token")

        mock_notify.assert_not_called()
        mock_file_issues.assert_not_called()

    def test_outer_failure_does_not_raise(self, db_session):
        with patch(
            "app.codescan.user_scan.list_target_repos", side_effect=RuntimeError("API down"),
        ), patch("app.codescan.user_scan.SessionLocal", return_value=db_session):
            run_codescan_for_user("octocat", "gho_token")  # 例外を送出しないことを確認
