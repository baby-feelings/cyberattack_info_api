"""app.depscan.user_scan（オンデマンド・ユーザー別スキャン）のテスト。"""
import os
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")


from app.depscan.models import DependencyFinding, UserScan  # noqa: E402
from tests.depscan.support import make_finding  # noqa: E402

TEST_API_KEY = "test-api-key-for-pytest"
HEADERS = {"X-API-KEY": TEST_API_KEY}
_NOW = datetime.now(UTC)
_REPO = "app.core.github.repo.GitHubRepo"

from app.depscan.user_scan import (  # noqa: E402
    get_user_scan_status,
    run_depscan_for_user,
    should_rescan_for_user,
)


class TestRunDepscanForUser:
    def test_success_path_records_done_status(self, db_session):
        with patch(
            "app.depscan.user_scan.collect_dependencies",
            return_value=(
                {("PyPI", "pkg", "1.0.0"): [("octocat/repo", "requirements.txt")]},
                1,
                {"octocat/repo": "public"},
            ),
        ), patch(
            "app.depscan.user_scan.build_findings",
            return_value=[{
                "repo_full_name": "octocat/repo", "ecosystem": "PyPI", "package_name": "pkg",
                "installed_version": "1.0.0", "osv_id": "GHSA-001", "severity": "HIGH",
                "cvss_score": 7.5, "summary": "vuln", "fixed_versions": [],
                "manifest_path": "requirements.txt", "detected_at": _NOW,
            }],
        ), patch("app.depscan.user_scan.SessionLocal", return_value=db_session):
            run_depscan_for_user("octocat", "gho_token")

        scan = db_session.query(UserScan).filter_by(username="octocat").first()
        assert scan.status == "done"
        assert scan.repos_scanned == 1
        assert scan.finished_at is not None
        findings_count = (
            db_session.query(DependencyFinding).filter_by(repo_full_name="octocat/repo").count()
        )
        assert findings_count == 1

    def test_does_not_resolve_other_owners_findings(self, db_session):
        """他オーナー（baby-feelings等）の未解決findingを誤って解決済みにしないこと。"""
        make_finding(db_session, repo_full_name="baby-feelings/baby_grow", osv_id="GHSA-untouched")

        with patch(
            "app.depscan.user_scan.collect_dependencies", return_value=({}, 0, {}),
        ), patch(
            "app.depscan.user_scan.build_findings", return_value=[],
        ), patch("app.depscan.user_scan.SessionLocal", return_value=db_session):
            run_depscan_for_user("octocat", "gho_token")

        untouched = db_session.query(DependencyFinding).filter_by(osv_id="GHSA-untouched").first()
        assert untouched.resolved_at is None

    def test_failure_records_error_status(self, db_session):
        with patch(
            "app.depscan.user_scan.collect_dependencies",
            side_effect=RuntimeError("GitHub API down"),
        ), patch("app.depscan.user_scan.SessionLocal", return_value=db_session):
            run_depscan_for_user("octocat", "gho_token")  # 例外を送出しないことを確認

        scan = db_session.query(UserScan).filter_by(username="octocat").first()
        assert scan.status == "error"
        assert "GitHub API down" in scan.error_message

    def test_notifies_and_files_issues_when_webhook_registered(self, db_session):
        """通知を有効にしてWebhookを登録済みのユーザーには、新規検知時にSlack通知と
        GitHub Issue起票の両方を行う（Issue #227）。"""
        from app.auth.account_store import set_slack_webhook, upsert_user_token

        upsert_user_token(db_session, "octocat", "gho_token")
        set_slack_webhook(db_session, "octocat", "https://hooks.slack.com/services/octocat")

        with patch(
            "app.depscan.user_scan.collect_dependencies",
            return_value=(
                {("PyPI", "pkg", "1.0.0"): [("octocat/repo", "requirements.txt")]},
                1,
                {"octocat/repo": "public"},
            ),
        ), patch(
            "app.depscan.user_scan.build_findings",
            return_value=[{
                "repo_full_name": "octocat/repo", "ecosystem": "PyPI", "package_name": "pkg",
                "installed_version": "1.0.0", "osv_id": "GHSA-001", "severity": "HIGH",
                "cvss_score": 7.5, "summary": "vuln", "fixed_versions": [],
                "manifest_path": "requirements.txt", "detected_at": _NOW,
            }],
        ), patch("app.depscan.user_scan.SessionLocal", return_value=db_session), \
           patch("app.depscan.user_scan.notify_dependency_findings") as mock_notify, \
           patch("app.depscan.user_scan.file_github_issues") as mock_file_issues:
            run_depscan_for_user("octocat", "gho_token")

        mock_notify.assert_called_once()
        assert mock_notify.call_args.kwargs["recipients"] == [
            "https://hooks.slack.com/services/octocat",
        ]
        mock_file_issues.assert_called_once()
        assert mock_file_issues.call_args[0][1] == "gho_token"

    def test_no_notification_when_webhook_not_registered(self, db_session):
        """Webhook未登録のユーザーには従来通り一切通知しない。"""
        with patch(
            "app.depscan.user_scan.collect_dependencies",
            return_value=(
                {("PyPI", "pkg", "1.0.0"): [("octocat/repo", "requirements.txt")]},
                1,
                {"octocat/repo": "public"},
            ),
        ), patch(
            "app.depscan.user_scan.build_findings",
            return_value=[{
                "repo_full_name": "octocat/repo", "ecosystem": "PyPI", "package_name": "pkg",
                "installed_version": "1.0.0", "osv_id": "GHSA-001", "severity": "HIGH",
                "cvss_score": 7.5, "summary": "vuln", "fixed_versions": [],
                "manifest_path": "requirements.txt", "detected_at": _NOW,
            }],
        ), patch("app.depscan.user_scan.SessionLocal", return_value=db_session), \
           patch("app.depscan.user_scan.notify_dependency_findings") as mock_notify, \
           patch("app.depscan.user_scan.file_github_issues") as mock_file_issues:
            run_depscan_for_user("octocat", "gho_token")

        mock_notify.assert_not_called()
        mock_file_issues.assert_not_called()

    def test_second_run_updates_existing_status_row(self, db_session):
        with patch(
            "app.depscan.user_scan.collect_dependencies", return_value=({}, 0, {}),
        ), patch(
            "app.depscan.user_scan.build_findings", return_value=[],
        ), patch("app.depscan.user_scan.SessionLocal", return_value=db_session):
            run_depscan_for_user("octocat", "gho_token")
            run_depscan_for_user("octocat", "gho_token")

        assert db_session.query(UserScan).filter_by(username="octocat").count() == 1


class TestGetUserScanStatus:
    def test_returns_none_when_never_scanned(self, db_session):
        assert get_user_scan_status(db_session, "nobody") is None

    def test_returns_recorded_scan(self, db_session):
        db_session.add(UserScan(
            username="octocat", status="done", repos_scanned=3,
            started_at=_NOW, finished_at=_NOW,
        ))
        db_session.commit()
        scan = get_user_scan_status(db_session, "octocat")
        assert scan is not None
        assert scan.status == "done"
        assert scan.repos_scanned == 3


class TestShouldRescanForUser:
    def test_no_scan_yet_returns_true(self, db_session):
        assert should_rescan_for_user(db_session, "octocat") is True

    def test_error_status_returns_true(self, db_session):
        db_session.add(UserScan(
            username="octocat", status="error", started_at=_NOW, finished_at=_NOW,
            error_message="boom",
        ))
        db_session.commit()
        assert should_rescan_for_user(db_session, "octocat") is True

    def test_running_status_returns_false(self, db_session):
        db_session.add(UserScan(username="octocat", status="running", started_at=_NOW))
        db_session.commit()
        assert should_rescan_for_user(db_session, "octocat") is False

    def test_recent_done_scan_returns_false(self, db_session):
        db_session.add(UserScan(
            username="octocat", status="done", started_at=_NOW, finished_at=_NOW,
        ))
        db_session.commit()
        assert should_rescan_for_user(db_session, "octocat") is False

    def test_stale_done_scan_returns_true(self, db_session):
        stale = _NOW - timedelta(hours=25)
        db_session.add(UserScan(
            username="octocat", status="done", started_at=stale, finished_at=stale,
        ))
        db_session.commit()
        assert should_rescan_for_user(db_session, "octocat") is True

    def test_stale_running_scan_returns_true(self, db_session):
        """デプロイ等でスレッドが強制終了され running のまま取り残されたケース
        （実際に本番で発生）。一定時間を超えたら stale とみなし再スキャンを許可する。"""
        from app.depscan.user_scan import STALE_RUNNING_THRESHOLD_MINUTES

        stale = _NOW - timedelta(minutes=STALE_RUNNING_THRESHOLD_MINUTES + 1)
        db_session.add(UserScan(username="octocat", status="running", started_at=stale))
        db_session.commit()
        assert should_rescan_for_user(db_session, "octocat") is True

    def test_recently_started_running_scan_returns_false(self, db_session):
        from app.depscan.user_scan import STALE_RUNNING_THRESHOLD_MINUTES

        recent = _NOW - timedelta(minutes=STALE_RUNNING_THRESHOLD_MINUTES - 1)
        db_session.add(UserScan(username="octocat", status="running", started_at=recent))
        db_session.commit()
        assert should_rescan_for_user(db_session, "octocat") is False
