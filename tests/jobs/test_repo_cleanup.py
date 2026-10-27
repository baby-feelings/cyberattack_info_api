"""app.jobs.repo_cleanup（削除済みリポジトリのデータ削除、Issue #228）のテスト。"""
from datetime import UTC, datetime
from unittest.mock import patch

import httpx

from app.codescan.models import CodeFinding
from app.crawler_logs.models import CrawlerLog
from app.depscan.models import DependencyFinding, RepoDependency
from app.depsops.models import DependabotPrLog
from app.jobs.repo_cleanup import purge_deleted_repos, run_repo_cleanup
from app.runtimes.models import RepoRuntime

_NOW = datetime.now(UTC)


_REPO = "app.core.github.repo.GitHubRepo"


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

        with patch(f"{_REPO}.exists", return_value=False):
            purged = purge_deleted_repos("baby-feelings", "token", current_repo_full_names=set())

        assert purged == 1
        assert db_session.query(DependencyFinding).count() == 0
        assert db_session.query(CodeFinding).count() == 0
        assert db_session.query(DependabotPrLog).count() == 0

    def test_purges_inventory_and_runtimes_even_without_any_finding(self, db_session):
        """検知が無く、依存の全量・使っている版だけが残っているリポジトリも、削除済みなら片付ける。"""
        db_session.add_all([
            RepoDependency(
                repo_full_name="baby-feelings/deleted-repo", ecosystem="npm",
                package_name="undici", version="8.12.3", manifest_path="package-lock.json",
            ),
            RepoRuntime(
                repo_full_name="baby-feelings/deleted-repo", runtime="python", cycle="3.13",
                source_path="Dockerfile", pinned=True,
            ),
            RepoRuntime(
                repo_full_name="baby-feelings/kept-repo", runtime="python", cycle="3.13",
                source_path="Dockerfile", pinned=True,
            ),
        ])
        db_session.commit()

        def exists(self):
            return self.full_name != "baby-feelings/deleted-repo"

        with patch(f"{_REPO}.exists", exists):
            purged = purge_deleted_repos(
                "baby-feelings", "token", current_repo_full_names={"baby-feelings/kept-repo"},
            )

        assert purged == 1
        assert db_session.query(RepoDependency).count() == 0
        assert [r.repo_full_name for r in db_session.query(RepoRuntime).all()] == [
            "baby-feelings/kept-repo"]

    def test_keeps_data_when_repo_still_exists(self, db_session):
        """アーカイブ化・可視性変更等で一覧から除外されているだけの場合は削除しない。"""
        _make_dependency_finding(db_session)

        with patch(f"{_REPO}.exists", return_value=True):
            purged = purge_deleted_repos("baby-feelings", "token", current_repo_full_names=set())

        assert purged == 0
        assert db_session.query(DependencyFinding).count() == 1

    def test_keeps_data_when_existence_check_is_inconclusive(self, db_session):
        """一時的なAPIエラー等で判定できない場合は安全側に倒し削除しない。"""
        _make_dependency_finding(db_session)

        with patch(f"{_REPO}.exists", return_value=None):
            purged = purge_deleted_repos("baby-feelings", "token", current_repo_full_names=set())

        assert purged == 0
        assert db_session.query(DependencyFinding).count() == 1

    def test_skips_repos_present_in_current_scan(self, db_session):
        _make_dependency_finding(db_session, repo_full_name="baby-feelings/still-there")

        with patch(f"{_REPO}.exists") as mock_exists:
            purged = purge_deleted_repos(
                "baby-feelings", "token",
                current_repo_full_names={"baby-feelings/still-there"},
            )

        assert purged == 0
        mock_exists.assert_not_called()

    def test_only_targets_repos_under_given_owner(self, db_session):
        """他オーナーのリポジトリは対象にしない。"""
        _make_dependency_finding(db_session, repo_full_name="other-owner/repo")

        with patch(f"{_REPO}.exists") as mock_exists:
            purged = purge_deleted_repos("baby-feelings", "token", current_repo_full_names=set())

        assert purged == 0
        mock_exists.assert_not_called()

    def test_returns_zero_when_nothing_to_check(self, db_session):
        purged = purge_deleted_repos("baby-feelings", "token", current_repo_full_names=set())
        assert purged == 0


class TestPurgeExcludedRepos:
    """対象外（SCAN_EXCLUDE_REPOS）のリポジトリは、実在していても、Issue を閉じてから削除する。"""

    _EXCLUDED = "baby-feelings/AppGoat_web_v305"
    _CFG = "app.core.github.accounts.settings.SCAN_EXCLUDE_REPOS"

    def _seed(self, db_session):
        _make_code_finding(db_session, repo_full_name=self._EXCLUDED)
        _make_code_finding(db_session, repo_full_name=self._EXCLUDED, line_start=2)
        _make_dependency_finding(db_session, repo_full_name=self._EXCLUDED)
        _make_code_finding(db_session, repo_full_name="baby-feelings/other")

    def test_closes_open_issues_then_purges_only_the_excluded_repo(self, db_session):
        self._seed(db_session)

        with patch(self._CFG, self._EXCLUDED), \
             patch(f"{_REPO}.exists") as exists, \
             patch(f"{_REPO}.find_open_issue", side_effect=[2, 7]) as find, \
             patch(f"{_REPO}.add_issue_comment") as comment, \
             patch(f"{_REPO}.close_issue") as close:
            purged = purge_deleted_repos(
                "baby-feelings", "token", current_repo_full_names={"baby-feelings/other"},
            )

        assert purged == 1
        exists.assert_not_called()  # 実在確認は不要（対象外なので、実在していても削除する）
        assert find.call_count == 2  # CODESCAN と DEPSCAN の Issue を探す
        assert [c.args[0] for c in comment.call_args_list] == [2, 7]
        assert [c.args[0] for c in close.call_args_list] == [2, 7]
        assert db_session.query(CodeFinding).filter_by(repo_full_name=self._EXCLUDED).count() == 0
        assert db_session.query(DependencyFinding).count() == 0
        assert db_session.query(CodeFinding).filter_by(
            repo_full_name="baby-feelings/other").count() == 1  # 他のリポジトリは残る

    def test_purges_when_there_is_no_open_issue(self, db_session):
        self._seed(db_session)

        with patch(self._CFG, self._EXCLUDED), \
             patch(f"{_REPO}.find_open_issue", return_value=None), \
             patch(f"{_REPO}.close_issue") as close:
            purged = purge_deleted_repos("baby-feelings", "token", current_repo_full_names=set())

        assert purged >= 1
        close.assert_not_called()
        assert db_session.query(CodeFinding).filter_by(repo_full_name=self._EXCLUDED).count() == 0

    def test_keeps_data_when_closing_the_issue_fails_so_it_retries_next_day(self, db_session):
        self._seed(db_session)

        with patch(self._CFG, self._EXCLUDED), \
             patch(f"{_REPO}.find_open_issue", side_effect=httpx.ConnectError("down")):
            purged = purge_deleted_repos(
                "baby-feelings", "token", current_repo_full_names={"baby-feelings/other"},
            )

        assert purged == 0
        # 先に消すと、このリポジトリを「データが残っているリポジトリ」として見つけられなくなる
        assert db_session.query(CodeFinding).filter_by(repo_full_name=self._EXCLUDED).count() == 2

    def test_does_nothing_when_no_repo_is_excluded(self, db_session):
        self._seed(db_session)

        with patch(self._CFG, ""), patch(f"{_REPO}.exists", return_value=True), \
             patch(f"{_REPO}.find_open_issue") as find:
            purged = purge_deleted_repos(
                "baby-feelings", "token", current_repo_full_names={"baby-feelings/other"},
            )

        assert purged == 0
        find.assert_not_called()
        assert db_session.query(CodeFinding).filter_by(repo_full_name=self._EXCLUDED).count() == 2


class TestRunRepoCleanup:
    def test_success_path_writes_crawler_log(self, db_session, monkeypatch):
        monkeypatch.setattr("app.jobs.repo_cleanup.settings.GITHUB_USERNAME", "baby-feelings")
        _make_dependency_finding(db_session, repo_full_name="baby-feelings/deleted-repo")
        repos = [{"full_name": "baby-feelings/kept-repo"}]

        with patch("app.jobs.repo_cleanup.list_target_repos", return_value=repos), \
             patch(f"{_REPO}.exists", return_value=False):
            purged = run_repo_cleanup()

        assert purged == 1
        log = db_session.query(CrawlerLog).filter_by(crawler_type="CLEANUP").first()
        assert log is not None
        assert log.status == "success"
        assert log.deleted == 1

    def test_failure_writes_error_log_and_reraises(self, db_session):
        with patch(
            "app.jobs.repo_cleanup.list_target_repos", side_effect=RuntimeError("API down"),
        ):
            try:
                run_repo_cleanup()
                raise AssertionError("expected RuntimeError")
            except RuntimeError:
                pass

        log = db_session.query(CrawlerLog).filter_by(crawler_type="CLEANUP").first()
        assert log is not None
        assert log.status == "error"
