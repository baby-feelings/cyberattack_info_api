"""app.core.repo_cleanup（削除済みリポジトリのデータ削除、Issue #228）のテスト。"""
from datetime import datetime, timezone
from unittest.mock import patch

from app.codescan.models import CodeFinding
from app.core.repo_cleanup import purge_deleted_repos, run_repo_cleanup
from app.crawler_logs.models import CrawlerLog
from app.depscan.models import DependencyFinding
from app.depsops.models import DependabotPrLog

_NOW = datetime.now(timezone.utc)


def _make_dependency_finding(db_session, **kwargs):
    defaults = {
        "repo_full_name": "baby-feelings/deleted-repo",
        "ecosystem": "PyPI", "package_name": "pkg", "installed_version": "1.0.0",
        "osv_id": "GHSA-001", "summary": "vuln", "fixed_versions": [],
        "manifest_path": "requirements.txt", "detected_at": _NOW,
    }
    defaults.update(kwargs)
    record = DependencyFinding(**defaults)
    db_session.add(record)
    db_session.commit()
    return record


def _make_code_finding(db_session, **kwargs):
    defaults = {
        "repo_full_name": "baby-feelings/deleted-repo",
        "file_path": "app.py", "line_start": 1, "line_end": 1,
        "rule_id": "rule", "message": "msg", "severity": "ERROR",
        "cwe_ids": [], "owasp_categories": [], "code_snippet": "x",
        "cvss_score": None, "cvss_vector": None, "detected_at": _NOW,
    }
    defaults.update(kwargs)
    record = CodeFinding(**defaults)
    db_session.add(record)
    db_session.commit()
    return record


def _make_pr_log(db_session, **kwargs):
    defaults = {
        "repo_full_name": "baby-feelings/deleted-repo",
        "pr_number": 1, "title": "Bump x", "action": "flagged", "reason": "major",
        "processed_at": _NOW,
    }
    defaults.update(kwargs)
    record = DependabotPrLog(**defaults)
    db_session.add(record)
    db_session.commit()
    return record


class TestPurgeDeletedRepos:
    def test_purges_confirmed_deleted_repo_across_all_domains(self, db_session):
        _make_dependency_finding(db_session)
        _make_code_finding(db_session)
        _make_pr_log(db_session)

        with patch("app.core.repo_cleanup.repo_exists", return_value=False):
            purged = purge_deleted_repos("baby-feelings", "token", current_repo_full_names=set())

        assert purged == 1
        assert db_session.query(DependencyFinding).count() == 0
        assert db_session.query(CodeFinding).count() == 0
        assert db_session.query(DependabotPrLog).count() == 0

    def test_keeps_data_when_repo_still_exists(self, db_session):
        """アーカイブ化・可視性変更等で一覧から除外されているだけの場合は削除しない。"""
        _make_dependency_finding(db_session)

        with patch("app.core.repo_cleanup.repo_exists", return_value=True):
            purged = purge_deleted_repos("baby-feelings", "token", current_repo_full_names=set())

        assert purged == 0
        assert db_session.query(DependencyFinding).count() == 1

    def test_keeps_data_when_existence_check_is_inconclusive(self, db_session):
        """一時的なAPIエラー等で判定できない場合は安全側に倒し削除しない。"""
        _make_dependency_finding(db_session)

        with patch("app.core.repo_cleanup.repo_exists", return_value=None):
            purged = purge_deleted_repos("baby-feelings", "token", current_repo_full_names=set())

        assert purged == 0
        assert db_session.query(DependencyFinding).count() == 1

    def test_skips_repos_present_in_current_scan(self, db_session):
        _make_dependency_finding(db_session, repo_full_name="baby-feelings/still-there")

        with patch("app.core.repo_cleanup.repo_exists") as mock_exists:
            purged = purge_deleted_repos(
                "baby-feelings", "token",
                current_repo_full_names={"baby-feelings/still-there"},
            )

        assert purged == 0
        mock_exists.assert_not_called()

    def test_only_targets_repos_under_given_owner(self, db_session):
        """他オーナーのリポジトリは対象にしない。"""
        _make_dependency_finding(db_session, repo_full_name="other-owner/repo")

        with patch("app.core.repo_cleanup.repo_exists") as mock_exists:
            purged = purge_deleted_repos("baby-feelings", "token", current_repo_full_names=set())

        assert purged == 0
        mock_exists.assert_not_called()

    def test_returns_zero_when_nothing_to_check(self, db_session):
        purged = purge_deleted_repos("baby-feelings", "token", current_repo_full_names=set())
        assert purged == 0


class TestRunRepoCleanup:
    def test_success_path_writes_crawler_log(self, db_session, monkeypatch):
        monkeypatch.setattr("app.core.repo_cleanup.settings.GITHUB_USERNAME", "baby-feelings")
        _make_dependency_finding(db_session, repo_full_name="baby-feelings/deleted-repo")
        repos = [{"full_name": "baby-feelings/kept-repo"}]

        with patch("app.core.repo_cleanup.list_target_repos", return_value=repos), \
             patch("app.core.repo_cleanup.repo_exists", return_value=False):
            purged = run_repo_cleanup()

        assert purged == 1
        log = db_session.query(CrawlerLog).filter_by(crawler_type="CLEANUP").first()
        assert log is not None
        assert log.status == "success"
        assert log.deleted == 1

    def test_failure_writes_error_log_and_reraises(self, db_session):
        with patch(
            "app.core.repo_cleanup.list_target_repos", side_effect=RuntimeError("API down"),
        ):
            try:
                run_repo_cleanup()
                raise AssertionError("expected RuntimeError")
            except RuntimeError:
                pass

        log = db_session.query(CrawlerLog).filter_by(crawler_type="CLEANUP").first()
        assert log is not None
        assert log.status == "error"
