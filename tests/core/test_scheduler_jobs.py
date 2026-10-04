"""app.core.scheduler_jobs（定期ジョブの定義と登録）のテスト。

`main.py` から切り出す前と同じジョブID・実行時刻・実行関数で登録されることを固定する
（本番のスケジュールが変わらないことの回帰ガード）。
"""
from unittest.mock import MagicMock

from app.codescan.crawler import fetch_and_scan_code
from app.core.config import settings
from app.core.repo_cleanup import run_repo_cleanup
from app.core.scheduler_jobs import ScheduledJob, build_scheduled_jobs, register_jobs
from app.core.user_crawl_runner import run_user_crawls_for_all_accounts
from app.depscan.crawler import fetch_and_scan_dependencies
from app.depsops.runner import run_dependabot_ops
from app.jvn.crawler import fetch_and_store_jvn
from app.kev.crawler import fetch_and_store_kev
from app.osv.crawler import fetch_and_store_osv


class TestBuildScheduledJobs:
    def test_defines_the_same_eight_jobs_as_before(self):
        jobs = {j.job_id: j for j in build_scheduled_jobs()}

        assert set(jobs) == {
            "cisa_kev_crawler", "osv_crawler", "jvn_crawler", "depscan_crawler",
            "codescan_crawler", "dependabot_ops", "repo_cleanup", "user_crawl",
        }
        expected = {
            "cisa_kev_crawler": (fetch_and_store_kev, settings.CRON_HOUR_UTC,
                                 settings.CRON_MINUTE_UTC),
            "osv_crawler": (fetch_and_store_osv, settings.OSV_CRON_HOUR_UTC, 0),
            "jvn_crawler": (fetch_and_store_jvn, settings.JVN_CRON_HOUR_UTC, 0),
            "depscan_crawler": (fetch_and_scan_dependencies, settings.DEPSCAN_CRON_HOUR_UTC, 0),
            "codescan_crawler": (fetch_and_scan_code, settings.CODESCAN_CRON_HOUR_UTC,
                                 settings.CODESCAN_CRON_MINUTE_UTC),
            "dependabot_ops": (run_dependabot_ops, settings.DEPSOPS_CRON_HOUR_UTC, 0),
            "repo_cleanup": (run_repo_cleanup, settings.REPO_CLEANUP_CRON_HOUR_UTC,
                             settings.REPO_CLEANUP_CRON_MINUTE_UTC),
            "user_crawl": (run_user_crawls_for_all_accounts, settings.USER_CRAWL_CRON_HOUR_UTC,
                           settings.USER_CRAWL_CRON_MINUTE_UTC),
        }
        for job_id, (func, hour, minute) in expected.items():
            job = jobs[job_id]
            assert (job.func, job.hour, job.minute) == (func, hour, minute), job_id

    def test_job_ids_are_unique(self):
        ids = [j.job_id for j in build_scheduled_jobs()]
        assert len(ids) == len(set(ids))


class TestRegisterJobs:
    def test_adds_each_job_as_daily_cron_and_starts_the_scheduler(self):
        scheduler = MagicMock()
        func = MagicMock()
        jobs = [ScheduledJob("a", "A", func, 3, 15), ScheduledJob("b", "B", func, 4)]

        register_jobs(scheduler, jobs)

        calls = scheduler.add_job.call_args_list
        assert [c.kwargs["id"] for c in calls] == ["a", "b"]
        assert calls[0].args == (func,)
        assert calls[0].kwargs == {
            "trigger": "cron", "hour": 3, "minute": 15, "id": "a", "replace_existing": True,
        }
        assert calls[1].kwargs["minute"] == 0  # 分の既定値は 0
        scheduler.start.assert_called_once()

    def test_starts_scheduler_after_all_jobs_are_registered(self):
        scheduler = MagicMock()
        order: list[str] = []
        scheduler.add_job.side_effect = lambda *a, **k: order.append("add")
        scheduler.start.side_effect = lambda: order.append("start")

        jobs = [ScheduledJob("a", "A", print, 1), ScheduledJob("b", "B", print, 2)]
        register_jobs(scheduler, jobs)

        assert order == ["add", "add", "start"]
