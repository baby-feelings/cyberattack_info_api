"""app.sla.digest（週次の対応状況まとめを送る定期ジョブ）のテスト。"""
import os
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.core.config import settings  # noqa: E402
from app.depscan.models import DependencyFinding  # noqa: E402
from app.sla.digest import run_sla_digest  # noqa: E402

WEBHOOK = ["https://hooks.slack.com/x"]


def _finding(repo, osv_id, *, detected_days_ago):
    return DependencyFinding(
        repo_full_name=repo, ecosystem="npm", package_name=f"pkg-{osv_id}",
        installed_version="1.0.0", osv_id=osv_id, severity="HIGH", summary="s",
        fixed_versions=[], cve_ids=[], manifest_path="package-lock.json",
        detected_at=datetime.now(UTC) - timedelta(days=detected_days_ago), resolved_at=None,
    )


def _run(db_session, findings):
    db_session.add_all(findings)
    db_session.commit()
    with patch(
        "app.core.notifications.recipients.resolve_admin_recipient", return_value=WEBHOOK,
    ), patch("app.core.notifications.slack.send_slack", return_value=True) as mock_send:
        sent = run_sla_digest()
    return sent, mock_send


class TestRunSlaDigest:
    def test_sends_the_digest_for_the_admins_own_repos_only(self, db_session):
        admin = settings.GITHUB_USERNAME
        sent, mock_send = _run(db_session, [
            _finding(f"{admin}/mine", "m1", detected_days_ago=50),
            _finding("someone-else/theirs", "o1", detected_days_ago=50),
        ])

        assert sent is True
        message = mock_send.call_args[0][0]
        assert f"{admin}/mine" in message
        assert "someone-else/theirs" not in message

    def test_excludes_inactive_repos(self, db_session):
        admin = settings.GITHUB_USERNAME
        with patch("app.core.operating_status.settings.INACTIVE_REPOS", f"{admin}/old"):
            sent, mock_send = _run(db_session, [
                _finding(f"{admin}/old", "x", detected_days_ago=50),
                _finding(f"{admin}/live", "y", detected_days_ago=50),
            ])

        message = mock_send.call_args[0][0]
        assert f"{admin}/live" in message
        assert f"{admin}/old" not in message

    def test_sends_an_all_clear_even_without_overdue_findings(self, db_session):
        sent, mock_send = _run(db_session, [])

        assert sent is True
        mock_send.assert_called_once()
        assert "期限超過: *0件*" in mock_send.call_args[0][0]

    def test_returns_false_when_there_is_no_destination(self, db_session):
        with patch(
            "app.core.notifications.recipients.resolve_admin_recipient", return_value=[],
        ), patch("app.core.notifications.slack.send_slack") as mock_send:
            sent = run_sla_digest()

        assert sent is False
        mock_send.assert_not_called()
