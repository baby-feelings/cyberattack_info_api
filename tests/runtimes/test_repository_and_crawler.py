"""app.runtimes.repository・crawler（保存と、毎日のクロール）のテスト。"""
import os
from datetime import date
from unittest.mock import MagicMock, patch

import httpx

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.crawler_logs.models import CrawlerLog  # noqa: E402
from app.runtimes.crawler import detect_repo_runtimes, fetch_and_scan_runtimes  # noqa: E402
from app.runtimes.detector import DetectedRuntime  # noqa: E402
from app.runtimes.eol_client import ReleaseInfo  # noqa: E402
from app.runtimes.models import RepoRuntime, RuntimeRelease  # noqa: E402
from app.runtimes.repository import RepoRuntimeRepository, RuntimeReleaseRepository  # noqa: E402


def _info(runtime="python", cycle="3.13", latest="3.13.17", eol=date(2029, 10, 31)):
    return ReleaseInfo(runtime, cycle, latest, date(2024, 10, 7), eol, False, False)


class TestRuntimeReleaseRepository:
    def test_inserts_then_updates_in_place(self, db_session):
        repo = RuntimeReleaseRepository(db_session)
        assert repo.upsert([_info(), _info("nodejs", "24", "24.1.0", None)]) == 2

        repo.upsert([_info(latest="3.13.18")])
        rows = db_session.query(RuntimeRelease).order_by(RuntimeRelease.runtime).all()
        assert len(rows) == 2
        assert {(r.runtime, r.latest_version) for r in rows} == {
            ("python", "3.13.18"), ("nodejs", "24.1.0")}

    def test_keeps_cycles_that_disappeared_from_the_source(self, db_session):
        repo = RuntimeReleaseRepository(db_session)
        repo.upsert([_info(cycle="3.9", latest="3.9.9"), _info()])
        repo.upsert([_info()])
        assert db_session.query(RuntimeRelease).count() == 2


class TestRepoRuntimeRepository:
    def test_replace_overwrites_the_repo_only(self, db_session):
        repo = RepoRuntimeRepository(db_session)
        repo.replace("alice/web", [DetectedRuntime("python", "3.12", "Dockerfile", True)])
        repo.replace("alice/api", [DetectedRuntime("nodejs", "22", "package.json", False)])

        saved = repo.replace("alice/web", [
            DetectedRuntime("python", "3.13", "Dockerfile", True),
            DetectedRuntime("python", "3.13", "Dockerfile", True),  # 重複は1件にまとめる
        ])

        assert saved == 1
        web = db_session.query(RepoRuntime).filter_by(repo_full_name="alice/web").all()
        assert [(r.cycle, r.pinned) for r in web] == [("3.13", True)]
        assert db_session.query(RepoRuntime).filter_by(repo_full_name="alice/api").count() == 1

    def test_replace_with_nothing_clears_the_repo(self, db_session):
        repo = RepoRuntimeRepository(db_session)
        repo.replace("alice/web", [DetectedRuntime("python", "3.12", "Dockerfile", True)])
        assert repo.replace("alice/web", []) == 0
        assert db_session.query(RepoRuntime).count() == 0


class TestRollbackOnFailure:
    """保存に失敗したときは、ロールバックして古い内容を残し、例外を呼び出し元へ伝える。"""

    def test_release_upsert_failure_rolls_back(self, db_session):
        RuntimeReleaseRepository(db_session).upsert([_info()])
        broken = ReleaseInfo("python", "3.14", "3.14.1", None, None, False, False)
        with patch.object(db_session, "commit", side_effect=RuntimeError("db down")):
            try:
                RuntimeReleaseRepository(db_session).upsert([_info(latest="9.9.9"), broken])
            except RuntimeError:
                pass
            else:
                raise AssertionError("expected RuntimeError")
        db_session.expire_all()
        assert db_session.query(RuntimeRelease).one().latest_version == "3.13.17"

    def test_repo_runtime_replace_failure_keeps_old_rows(self, db_session):
        repo = RepoRuntimeRepository(db_session)
        repo.replace("alice/web", [DetectedRuntime("python", "3.12", "Dockerfile", True)])
        with patch.object(db_session, "commit", side_effect=RuntimeError("db down")):
            try:
                repo.replace("alice/web", [DetectedRuntime("python", "3.13", "Dockerfile", True)])
            except RuntimeError:
                pass
            else:
                raise AssertionError("expected RuntimeError")
        db_session.expire_all()
        assert [r.cycle for r in db_session.query(RepoRuntime).all()] == ["3.12"]


class TestDetectRepoRuntimes:
    def _repo(self, tree, files):
        repo = MagicMock()
        repo.full_name = "alice/web"
        repo.tree.return_value = tree
        repo.file_content.side_effect = lambda path: files[path]
        return repo

    def test_reads_only_candidate_files_outside_excluded_dirs(self):
        repo = self._repo(
            ["Dockerfile", "src/main.py", "node_modules/x/package.json", "docs/readme.md"],
            {"Dockerfile": "FROM python:3.13-slim\n"},
        )
        found = detect_repo_runtimes(repo, "main")
        assert found == [DetectedRuntime("python", "3.13", "Dockerfile", True)]
        repo.file_content.assert_called_once_with("Dockerfile")

    def test_returns_none_when_tree_cannot_be_fetched(self):
        repo = MagicMock()
        repo.full_name = "alice/web"
        repo.tree.side_effect = httpx.ConnectError("boom")
        assert detect_repo_runtimes(repo, "main") is None

    def test_skips_files_that_fail_to_fetch(self):
        repo = MagicMock()
        repo.full_name = "alice/web"
        repo.tree.return_value = ["Dockerfile", ".nvmrc"]
        repo.file_content.side_effect = lambda path: (
            (_ for _ in ()).throw(httpx.ReadTimeout("slow")) if path == "Dockerfile" else "24\n"
        )
        found = detect_repo_runtimes(repo, "main")
        assert found == [DetectedRuntime("nodejs", "24", ".nvmrc", True)]

    def test_skips_oversized_files(self):
        repo = self._repo(["Dockerfile"], {"Dockerfile": "FROM python:3.13\n" + "#" * 400_000})
        assert detect_repo_runtimes(repo, "main") == []


class TestFetchAndScanRuntimes:
    def _run(self, repos, detected_by_repo, *, force=True):
        def fake_detect(repo, branch):
            return detected_by_repo[repo.full_name]

        with (
            patch("app.runtimes.crawler.fetch_all_releases", return_value=[_info()]),
            patch("app.runtimes.crawler.list_target_repos", return_value=repos),
            patch("app.runtimes.crawler.detect_repo_runtimes", side_effect=fake_detect),
        ):
            return fetch_and_scan_runtimes(force=force)

    def test_saves_releases_and_usage_and_logs_success(self, db_session):
        repos = [{"full_name": "alice/web", "default_branch": "main"}]
        detected = {"alice/web": [DetectedRuntime("python", "3.13", "Dockerfile", True)]}

        result = self._run(repos, detected)

        assert result == (1, 1, 0)  # (検出した版, 更新したリリース情報, 0)
        assert db_session.query(RuntimeRelease).count() == 1
        assert db_session.query(RepoRuntime).count() == 1
        log = db_session.query(CrawlerLog).filter_by(crawler_type="RUNTIME").one()
        assert log.status == "success"

    def test_unreachable_repo_keeps_previous_rows(self, db_session):
        RepoRuntimeRepository(db_session).replace(
            "alice/web", [DetectedRuntime("python", "3.12", "Dockerfile", True)])
        repos = [{"full_name": "alice/web", "default_branch": "main"}]

        self._run(repos, {"alice/web": None})

        assert db_session.query(RepoRuntime).one().cycle == "3.12"

    def test_one_repo_failing_to_save_does_not_stop_the_others(self, db_session):
        repos = [
            {"full_name": "alice/a", "default_branch": "main"},
            {"full_name": "alice/b", "default_branch": "main"},
        ]
        detected = {
            "alice/a": [DetectedRuntime("python", "3.13", "Dockerfile", True)],
            "alice/b": [DetectedRuntime("nodejs", "24", ".nvmrc", True)],
        }
        original = RepoRuntimeRepository.replace

        def flaky(self, full_name, items):
            if full_name == "alice/a":
                raise RuntimeError("db down")
            return original(self, full_name, items)

        with patch.object(RepoRuntimeRepository, "replace", flaky):
            self._run(repos, detected)

        assert [r.repo_full_name for r in db_session.query(RepoRuntime).all()] == ["alice/b"]

    def test_release_fetch_failure_fails_the_crawl_and_is_logged(self, db_session):
        with (
            patch("app.runtimes.crawler.fetch_all_releases", side_effect=httpx.ConnectError("x")),
            patch("app.core.crawler_runner.notify_error"),
        ):
            try:
                fetch_and_scan_runtimes(force=True)
            except httpx.ConnectError:
                pass
            else:
                raise AssertionError("expected ConnectError")
        log = db_session.query(CrawlerLog).filter_by(crawler_type="RUNTIME").one()
        assert log.status == "error"

    def test_skips_when_already_succeeded_today(self, db_session):
        repos = [{"full_name": "alice/web", "default_branch": "main"}]
        detected = {"alice/web": [DetectedRuntime("python", "3.13", "Dockerfile", True)]}
        self._run(repos, detected)

        assert self._run(repos, detected, force=False) == (0, 0, 0)


class TestAlertsAfterTheCrawl:
    """毎日の実行が成功したあとに、変化があったときだけ通知する。通知の失敗でクロールを失敗にしない。"""

    def _repos(self):
        return [{"full_name": "alice/web", "default_branch": "main"}]

    def _detected(self):
        return {"alice/web": [DetectedRuntime("python", "3.13", "Dockerfile", True)]}

    def test_sends_alerts_after_a_successful_crawl(self, db_session):
        with patch("app.runtimes.crawler.send_runtime_alerts") as send:
            TestFetchAndScanRuntimes()._run(self._repos(), self._detected())
        send.assert_called_once_with()

    def test_not_sent_when_the_crawl_fails(self, db_session):
        with (
            patch("app.runtimes.crawler.fetch_all_releases", side_effect=httpx.ConnectError("x")),
            patch("app.core.crawler_runner.notify_error"),
            patch("app.runtimes.crawler.send_runtime_alerts") as send,
        ):
            try:
                fetch_and_scan_runtimes(force=True)
            except httpx.ConnectError:
                pass
        send.assert_not_called()

    def test_alert_failure_does_not_fail_the_crawl(self, db_session):
        with patch("app.runtimes.crawler.send_runtime_alerts", side_effect=RuntimeError("slack")):
            result = TestFetchAndScanRuntimes()._run(self._repos(), self._detected())
        assert result == (1, 1, 0)
        log = db_session.query(CrawlerLog).filter_by(crawler_type="RUNTIME").one()
        assert log.status == "success"
