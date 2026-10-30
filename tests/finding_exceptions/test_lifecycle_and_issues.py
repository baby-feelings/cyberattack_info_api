"""期限・修正版の公開の確認と、Issue の整合、クローラー・Issue クローズへの反映のテスト。"""
import os
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.core.database import SessionLocal  # noqa: E402
from app.depscan.issue_management import close_resolved_repo_issues  # noqa: E402
from app.depscan.models import DependencyFinding  # noqa: E402
from app.finding_exceptions.issue_sync import (  # noqa: E402
    is_admin_repo,
    refile_issues,
    sync_issues_after_change,
)
from app.finding_exceptions.lifecycle import run_exception_lifecycle  # noqa: E402
from app.finding_exceptions.models import FindingException  # noqa: E402
from tests.conftest import TestSessionLocal  # noqa: E402

NOW = datetime.now(UTC)
ADMIN = "test-github-user"
_REPO = "app.core.github.repo.GitHubRepo"


def _dep(repo=f"{ADMIN}/api", osv="GHSA-1", fixed=None, resolved=False):
    return DependencyFinding(
        repo_full_name=repo, ecosystem="npm", package_name="lodash", installed_version="4.0.0",
        osv_id=osv, severity="HIGH", summary="s", fixed_versions=fixed or [], cve_ids=[],
        manifest_path="package-lock.json", detected_at=NOW,
        resolved_at=NOW if resolved else None,
    )


def _exc(db, *, repo=f"{ADMIN}/api", key="npm|lodash|GHSA-1", status="accepted",
         expires_in_days=30, kind="dependency"):
    row = FindingException(
        kind=kind, repo_full_name=repo, finding_key=key, status=status, reason="修正版が無い",
        approver=ADMIN, expires_at=NOW + timedelta(days=expires_in_days)
        if expires_in_days is not None else None,
    )
    db.add(row)
    db.commit()
    return row


def _run(**kwargs):
    """定期ジョブを実行する（通知・Issue は差し替え、送られた内容を返す）。"""
    with patch("app.finding_exceptions.lifecycle.SessionLocal", TestSessionLocal), \
         patch("app.finding_exceptions.lifecycle.refile_issues") as refile, \
         patch("app.finding_exceptions.lifecycle.ExceptionNoticeNotifier") as notifier:
        counts = run_exception_lifecycle(**kwargs)
    return counts, refile, notifier


class TestLifecycle:
    def test_accepted_exception_ends_when_a_fix_is_published(self, db_session):
        db_session.add(_dep(fixed=["4.17.21"]))
        row = _exc(db_session)

        counts, refile, notifier = _run()

        db_session.refresh(row)
        assert (row.ended_reason, row.ended_at is not None) == ("fix_available", True)
        assert counts == {"fixed": 1, "expired": 0, "soon": 0}
        notices = notifier.call_args.args[0]
        assert notices["fixed"][0]["label"] == "npm / lodash / GHSA-1"
        # 解除した検知は、Issue に再び示す
        assert refile.call_args.args[1][0].id == row.id
        notifier.return_value.send.assert_called_once()

    def test_accepted_exception_stays_while_there_is_no_fix(self, db_session):
        db_session.add(_dep(fixed=[]))
        row = _exc(db_session)

        counts, _, _ = _run()

        db_session.refresh(row)
        assert row.ended_at is None
        assert counts == {"fixed": 0, "expired": 0, "soon": 0}

    def test_not_affected_is_kept_even_if_a_fix_is_published(self, db_session):
        db_session.add(_dep(fixed=["4.17.21"]))
        row = _exc(db_session, status="not_affected", expires_in_days=None)

        _run()

        db_session.refresh(row)
        assert row.ended_at is None

    def test_expired_exception_ends_and_is_reported(self, db_session):
        db_session.add(_dep())
        row = _exc(db_session, expires_in_days=-1)

        counts, refile, notifier = _run()

        db_session.refresh(row)
        assert row.ended_reason == "expired"
        assert counts["expired"] == 1
        assert notifier.call_args.args[0]["expired"][0]["repo_full_name"] == f"{ADMIN}/api"
        assert refile.call_args.args[1][0].id == row.id

    def test_expired_exception_for_a_resolved_finding_is_ended_silently(self, db_session):
        db_session.add(_dep(resolved=True))
        row = _exc(db_session, expires_in_days=-1)

        counts, _, _ = _run()

        db_session.refresh(row)
        assert row.ended_reason == "expired"
        assert counts["expired"] == 0

    def test_exception_nearing_expiry_is_notified_once(self, db_session):
        db_session.add(_dep())
        _exc(db_session, expires_in_days=3)

        first, _, notifier = _run()
        second, _, _ = _run()

        assert first["soon"] == 1 and second["soon"] == 0
        assert notifier.call_args.args[0]["soon"][0]["expires_at"] is not None

    def test_exception_far_from_expiry_is_not_notified(self, db_session):
        db_session.add(_dep())
        _exc(db_session, expires_in_days=60)

        counts, _, _ = _run()

        assert counts["soon"] == 0

    def test_other_owners_exceptions_are_updated_but_not_notified(self, db_session):
        db_session.add(_dep(repo="stranger/app"))
        row = _exc(db_session, repo="stranger/app", expires_in_days=-1)

        counts, refile, _ = _run()

        db_session.refresh(row)
        assert row.ended_reason == "expired"
        assert counts == {"fixed": 0, "expired": 0, "soon": 0}
        assert refile.call_args.args[1] == []

    def test_nothing_to_do_sends_nothing(self, db_session):
        with patch("app.finding_exceptions.lifecycle.SessionLocal", TestSessionLocal), \
             patch("app.core.notifications.slack.send_slack") as send:
            counts = run_exception_lifecycle()

        assert counts == {"fixed": 0, "expired": 0, "soon": 0}
        send.assert_not_called()


class TestIssueSync:
    """Issue の整合は、管理者のトークンで書き込むため、管理者のリポジトリだけが対象。"""

    ADMIN_REPO = f"{ADMIN}/app"

    def _session_patch(self):
        return patch("app.finding_exceptions.issue_sync.SessionLocal", TestSessionLocal)

    def test_accepting_closes_the_dependency_issue_when_nothing_actionable_remains(self):
        with self._session_patch(), \
             patch("app.finding_exceptions.issue_sync.close_resolved_repo_issues") as close:
            sync_issues_after_change("dependency", self.ADMIN_REPO, "k", accepted=True)

        assert close.call_args.args[1] == {self.ADMIN_REPO}

    def test_accepting_a_code_finding_does_not_touch_issues(self):
        with self._session_patch(), \
             patch("app.finding_exceptions.issue_sync.close_resolved_repo_issues") as close, \
             patch("app.finding_exceptions.issue_sync.refile_issues") as refile:
            sync_issues_after_change("code", self.ADMIN_REPO, "k", accepted=True)

        close.assert_not_called()
        refile.assert_not_called()

    def test_revoking_shows_the_finding_in_the_issue_again(self, db_session):
        db_session.add(_dep(repo=self.ADMIN_REPO))
        db_session.commit()
        with self._session_patch(), \
             patch("app.finding_exceptions.issue_sync.file_dependency_issues") as dep_issue, \
             patch("app.finding_exceptions.issue_sync.file_code_issues") as code_issue:
            sync_issues_after_change(
                "dependency", self.ADMIN_REPO, "npm|lodash|GHSA-1", accepted=False,
            )

        assert dep_issue.call_args.args[0][0]["osv_id"] == "GHSA-1"
        assert code_issue.call_args.args[0] == []

    def test_other_owners_repositories_are_never_written_with_the_admin_token(self):
        # セキュリティ: 他のユーザーが例外を登録・解除しても、管理者のトークンでは書き込まない
        with self._session_patch(), \
             patch("app.finding_exceptions.issue_sync.close_resolved_repo_issues") as close, \
             patch("app.finding_exceptions.issue_sync.refile_issues") as refile:
            sync_issues_after_change("dependency", "stranger/app", "k", accepted=True)
            sync_issues_after_change("dependency", "stranger/app", "k", accepted=False)

        close.assert_not_called()
        refile.assert_not_called()

    def test_is_admin_repo_ignores_case_and_requires_the_owner_prefix(self):
        assert is_admin_repo(f"{ADMIN.upper()}/x") is True
        assert is_admin_repo(f"{ADMIN}-evil/x") is False
        assert is_admin_repo(f"other/{ADMIN}") is False

    def test_failures_are_swallowed(self):
        with self._session_patch(), \
             patch("app.finding_exceptions.issue_sync.close_resolved_repo_issues",
                   side_effect=RuntimeError("boom")):
            sync_issues_after_change(
                "dependency", self.ADMIN_REPO, "k", accepted=True,
            )  # 例外を送出しない

    def test_refile_swallows_github_errors(self, db_session):
        db_session.add(_dep(repo="u/app"))
        db_session.commit()
        exc = FindingException(kind="dependency", repo_full_name="u/app",
                               finding_key="npm|lodash|GHSA-1")
        with patch("app.finding_exceptions.issue_sync.file_dependency_issues",
                   side_effect=RuntimeError("boom")):
            refile_issues(db_session, [exc])  # 例外を送出しない

    def test_session_factory_is_the_applications(self):
        assert SessionLocal is not None


class TestCloseResolvedRepoIssuesIgnoresExceptions:
    def test_closes_when_every_remaining_finding_has_an_exception(self, db_session):
        db_session.add(_dep(repo="u/app"))
        db_session.add(FindingException(
            kind="dependency", repo_full_name="u/app", finding_key="npm|lodash|GHSA-1",
            status="accepted", reason="r", approver="u", expires_at=NOW + timedelta(days=5)))
        db_session.commit()

        with patch(f"{_REPO}.find_open_issue", autospec=True, return_value=7), \
             patch(f"{_REPO}.add_issue_comment", autospec=True), \
             patch(f"{_REPO}.close_issue", autospec=True) as close:
            close_resolved_repo_issues(db_session, {"u/app"})

        close.assert_called_once()

    def test_does_not_close_when_a_finding_without_an_exception_remains(self, db_session):
        db_session.add_all([_dep(repo="u/app"), _dep(repo="u/app", osv="GHSA-2")])
        db_session.add(FindingException(
            kind="dependency", repo_full_name="u/app", finding_key="npm|lodash|GHSA-1",
            status="accepted", reason="r", approver="u", expires_at=NOW + timedelta(days=5)))
        db_session.commit()

        with patch(f"{_REPO}.find_open_issue", autospec=True) as find, \
             patch(f"{_REPO}.close_issue", autospec=True) as close:
            close_resolved_repo_issues(db_session, {"u/app"})

        find.assert_not_called()
        close.assert_not_called()

    def test_an_expired_exception_keeps_the_issue_open(self, db_session):
        db_session.add(_dep(repo="u/app"))
        db_session.add(FindingException(
            kind="dependency", repo_full_name="u/app", finding_key="npm|lodash|GHSA-1",
            status="accepted", reason="r", approver="u", expires_at=NOW - timedelta(days=1)))
        db_session.commit()

        with patch(f"{_REPO}.find_open_issue", autospec=True) as find:
            close_resolved_repo_issues(db_session, {"u/app"})

        find.assert_not_called()


class TestCrawlersSkipExceptedNewFindings:
    def test_dependency_crawler_does_not_notify_an_excepted_recurrence(self, db_session):
        from app.depscan.crawler import _DepscanJob as DepscanCrawlJob

        db_session.add(FindingException(
            kind="dependency", repo_full_name="u/app", finding_key="npm|lodash|GHSA-1",
            status="accepted", reason="r", approver="u", expires_at=NOW + timedelta(days=5)))
        db_session.commit()
        records = [
            {"repo_full_name": "u/app", "ecosystem": "npm", "package_name": "lodash",
             "installed_version": "4.0.0", "osv_id": "GHSA-1", "severity": "HIGH",
             "cvss_score": None, "summary": "s", "fixed_versions": [], "cve_ids": [],
             "manifest_path": "package-lock.json", "reachability": None,
             "repo_visibility": "private", "detected_at": NOW},
            {"repo_full_name": "u/app", "ecosystem": "npm", "package_name": "lodash",
             "installed_version": "4.0.0", "osv_id": "GHSA-2", "severity": "HIGH",
             "cvss_score": None, "summary": "s", "fixed_versions": [], "cve_ids": [],
             "manifest_path": "package-lock.json", "reachability": None,
             "repo_visibility": "private", "detected_at": NOW},
        ]
        job = DepscanCrawlJob()
        counters = MagicMock()
        with patch("app.depscan.crawler.collect_dependencies",
                   return_value=({}, 1, {"u/app": "private"})), \
             patch("app.depscan.crawler.RepoDependencyRepository"), \
             patch("app.depscan.crawler.build_findings", return_value=records), \
             patch("app.depscan.crawler.apply_reachability"), \
             patch("app.depscan.crawler.close_resolved_repo_issues"):
            job.execute(db_session, counters)

        # DB には2件とも入る（一覧で確認できる）が、通知・起票の対象は、例外のない1件だけ
        assert db_session.query(DependencyFinding).count() == 2
        assert [s["osv_id"] for s in job.new_snapshots] == ["GHSA-2"]
