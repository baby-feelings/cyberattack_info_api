"""app.jobs.scheduler_jobs（定期ジョブの定義と登録）のテスト。

`main.py` から切り出す前と同じジョブID・実行時刻・実行関数で登録されることを固定する
（本番のスケジュールが変わらないことの回帰ガード）。
"""
from unittest.mock import MagicMock

from app.codescan.crawler import fetch_and_scan_code
from app.commit_watch.crawler import fetch_and_watch_commits
from app.core.config import settings
from app.depscan.crawler import fetch_and_scan_dependencies
from app.depsops.runner import run_dependabot_ops
from app.external_monitor.crawler import fetch_and_monitor_sites
from app.finding_exceptions.lifecycle import run_exception_lifecycle
from app.github_alerts.crawler import fetch_and_store_github_alerts
from app.jobs.repo_cleanup import run_repo_cleanup
from app.jobs.scheduler_jobs import ScheduledJob, build_scheduled_jobs, register_jobs
from app.jobs.secret_expiry import run_secret_expiry_notice
from app.jobs.user_crawl_runner import run_user_crawls_for_all_accounts
from app.jvn.crawler import fetch_and_store_jvn
from app.kev.crawler import fetch_and_store_kev
from app.mcp_server.mcp_token_expiry import run_mcp_token_expiry_notices
from app.mcp_server.oauth.cleanup import run_oauth_cleanup
from app.osv.crawler import fetch_and_store_osv
from app.repo_audit.crawler import fetch_and_audit_repos
from app.runtimes.crawler import fetch_and_scan_runtimes
from app.sla.digest import run_sla_digest


class TestBuildScheduledJobs:
    def test_defines_the_expected_jobs(self):
        jobs = {j.job_id: j for j in build_scheduled_jobs()}

        assert set(jobs) == {
            "cisa_kev_crawler", "osv_crawler", "jvn_crawler", "depscan_crawler",
            "codescan_crawler", "dependabot_ops", "repo_cleanup", "user_crawl",
            "mcp_token_expiry_notice", "oauth_cleanup", "runtime_crawler", "sla_digest",
            "exception_lifecycle", "github_alerts", "repo_audit",
            "site_monitor", "commit_watch", "secret_expiry",
        }
        expected = {
            "cisa_kev_crawler": (fetch_and_store_kev, settings.CRON_HOUR_UTC,
                                 settings.CRON_MINUTE_UTC),
            "osv_crawler": (fetch_and_store_osv, settings.OSV_CRON_HOUR_UTC, 0),
            "jvn_crawler": (fetch_and_store_jvn, settings.JVN_CRON_HOUR_UTC, 0),
            "depscan_crawler": (fetch_and_scan_dependencies, settings.DEPSCAN_CRON_HOUR_UTC, 0),
            "codescan_crawler": (fetch_and_scan_code, settings.CODESCAN_CRON_HOUR_UTC,
                                 settings.CODESCAN_CRON_MINUTE_UTC),
            "runtime_crawler": (fetch_and_scan_runtimes, settings.RUNTIME_CRON_HOUR_UTC,
                                settings.RUNTIME_CRON_MINUTE_UTC),
            "dependabot_ops": (run_dependabot_ops, settings.DEPSOPS_CRON_HOUR_UTC, 0),
            "repo_cleanup": (run_repo_cleanup, settings.REPO_CLEANUP_CRON_HOUR_UTC,
                             settings.REPO_CLEANUP_CRON_MINUTE_UTC),
            "user_crawl": (run_user_crawls_for_all_accounts, settings.USER_CRAWL_CRON_HOUR_UTC,
                           settings.USER_CRAWL_CRON_MINUTE_UTC),
            "mcp_token_expiry_notice": (run_mcp_token_expiry_notices,
                                        settings.MCP_EXPIRY_NOTICE_CRON_HOUR_UTC,
                                        settings.MCP_EXPIRY_NOTICE_CRON_MINUTE_UTC),
            "oauth_cleanup": (run_oauth_cleanup, settings.OAUTH_CLEANUP_CRON_HOUR_UTC,
                              settings.OAUTH_CLEANUP_CRON_MINUTE_UTC),
            "sla_digest": (run_sla_digest, settings.SLA_DIGEST_CRON_HOUR_UTC,
                           settings.SLA_DIGEST_CRON_MINUTE_UTC),
            "secret_expiry": (run_secret_expiry_notice, settings.SECRET_EXPIRY_CRON_HOUR_UTC,
                              settings.SECRET_EXPIRY_CRON_MINUTE_UTC),
            "commit_watch": (fetch_and_watch_commits, settings.COMMITWATCH_CRON_HOUR_UTC,
                             settings.COMMITWATCH_CRON_MINUTE_UTC),
            "site_monitor": (fetch_and_monitor_sites, settings.EXTMON_CRON_HOUR_UTC,
                             settings.EXTMON_CRON_MINUTE_UTC),
            "repo_audit": (fetch_and_audit_repos, settings.REPOAUDIT_CRON_HOUR_UTC,
                           settings.REPOAUDIT_CRON_MINUTE_UTC),
            "github_alerts": (fetch_and_store_github_alerts, settings.GHALERT_CRON_HOUR_UTC,
                              settings.GHALERT_CRON_MINUTE_UTC),
            "exception_lifecycle": (run_exception_lifecycle, settings.EXCEPTION_CRON_HOUR_UTC,
                                    settings.EXCEPTION_CRON_MINUTE_UTC),
        }
        for job_id, (func, hour, minute) in expected.items():
            job = jobs[job_id]
            assert (job.func, job.hour, job.minute) == (func, hour, minute), job_id

    def test_only_the_sla_digest_is_weekly(self):
        # 週次のまとめだけ曜日を持つ。他は毎日（曜日なし）
        days = {j.job_id: j.day_of_week for j in build_scheduled_jobs()}

        assert days.pop("sla_digest") == settings.SLA_DIGEST_DAY_OF_WEEK
        assert all(day is None for day in days.values())

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
            "trigger": "cron", "hour": 3, "minute": 15, "day_of_week": None,
            "id": "a", "replace_existing": True,
        }
        assert calls[1].kwargs["minute"] == 0  # 分の既定値は 0
        scheduler.start.assert_called_once()

    def test_weekly_job_is_registered_with_its_day_of_week(self):
        scheduler = MagicMock()
        func = MagicMock()

        register_jobs(scheduler, [ScheduledJob("w", "W", func, 0, 0, day_of_week="mon")])

        kwargs = scheduler.add_job.call_args.kwargs
        assert (kwargs["day_of_week"], kwargs["hour"], kwargs["minute"]) == ("mon", 0, 0)

    def test_starts_scheduler_after_all_jobs_are_registered(self):
        scheduler = MagicMock()
        order: list[str] = []
        scheduler.add_job.side_effect = lambda *a, **k: order.append("add")
        scheduler.start.side_effect = lambda: order.append("start")

        jobs = [ScheduledJob("a", "A", print, 1), ScheduledJob("b", "B", print, 2)]
        register_jobs(scheduler, jobs)

        assert order == ["add", "add", "start"]
