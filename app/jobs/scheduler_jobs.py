"""APScheduler に登録する定期ジョブの定義と登録処理。

`app/main.py` の `_register_scheduled_jobs` が 8 本のジョブを `add_job` で個別に並べていたものを、
「ジョブ定義（`ScheduledJob`）」と「登録ループ（`register_jobs`）」に分ける。`main.py` は
ルーター include・lifespan のみに専念する方針のため、スケジュール定義はここへ移す。

ジョブを足すときは `build_scheduled_jobs` の一覧に `ScheduledJob` を1行足すだけでよい
（実行時刻は `settings.*_CRON_*` から読む。依存する前段ジョブの後ろに並べる）。
"""
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from apscheduler.schedulers.background import BackgroundScheduler

from app.codescan.crawler import fetch_and_scan_code
from app.core.config import settings
from app.depscan.crawler import fetch_and_scan_dependencies
from app.depsops.runner import run_dependabot_ops
from app.external_monitor.crawler import fetch_and_monitor_sites
from app.finding_exceptions.lifecycle import run_exception_lifecycle
from app.github_alerts.crawler import fetch_and_store_github_alerts
from app.jobs.repo_cleanup import run_repo_cleanup
from app.jobs.user_crawl_runner import run_user_crawls_for_all_accounts
from app.jvn.crawler import fetch_and_store_jvn
from app.kev.crawler import fetch_and_store_kev
from app.mcp_server.mcp_token_expiry import run_mcp_token_expiry_notices
from app.mcp_server.oauth.cleanup import run_oauth_cleanup
from app.osv.crawler import fetch_and_store_osv
from app.repo_audit.crawler import fetch_and_audit_repos
from app.runtimes.crawler import fetch_and_scan_runtimes
from app.sla.digest import run_sla_digest

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScheduledJob:
    """毎日1回の cron ジョブ（UTC の時・分で実行する）。"""

    job_id: str
    label: str
    func: Callable[..., Any]
    hour: int
    minute: int = 0
    # 曜日（"mon" など）。None なら毎日。週次ジョブだけ指定する
    day_of_week: str | None = None


def build_scheduled_jobs() -> list[ScheduledJob]:
    """登録するジョブの一覧（実行順の目安: KEV/OSV/JVN → DEPSCAN → CODESCAN → DEPSOPS →
    削除済みリポジトリの掃除 → 登録ユーザー向け）。"""
    return [
        # CISA KEV クローラー: 毎日 UTC 19:00（JST 翌日 4:00）
        ScheduledJob(
            "cisa_kev_crawler", "KEV", fetch_and_store_kev,
            settings.CRON_HOUR_UTC, settings.CRON_MINUTE_UTC,
        ),
        ScheduledJob("osv_crawler", "OSV", fetch_and_store_osv, settings.OSV_CRON_HOUR_UTC),
        ScheduledJob("jvn_crawler", "JVN", fetch_and_store_jvn, settings.JVN_CRON_HOUR_UTC),
        # 依存ライブラリ脆弱性スキャナー（DEPSCAN）
        ScheduledJob(
            "depscan_crawler", "DEPSCAN", fetch_and_scan_dependencies,
            settings.DEPSCAN_CRON_HOUR_UTC,
        ),
        # 自アプリコード脆弱性診断（CODESCAN）: DEPSCAN の後段に配置
        ScheduledJob(
            "codescan_crawler", "CODESCAN", fetch_and_scan_code,
            settings.CODESCAN_CRON_HOUR_UTC, settings.CODESCAN_CRON_MINUTE_UTC,
        ),
        # 言語・実行環境のバージョン監視（RUNTIME）: CODESCAN の後段に配置
        ScheduledJob(
            "runtime_crawler", "RUNTIME", fetch_and_scan_runtimes,
            settings.RUNTIME_CRON_HOUR_UTC, settings.RUNTIME_CRON_MINUTE_UTC,
        ),
        # Dependabot PR 自動運用（DEPSOPS）
        ScheduledJob(
            "dependabot_ops", "DEPSOPS", run_dependabot_ops, settings.DEPSOPS_CRON_HOUR_UTC,
        ),
        # 削除済みリポジトリのDEPSCAN/CODESCAN/DEPSOPSデータ削除（Issue #228）: DEPSOPSの後段
        ScheduledJob(
            "repo_cleanup", "REPO_CLEANUP", run_repo_cleanup,
            settings.REPO_CLEANUP_CRON_HOUR_UTC, settings.REPO_CLEANUP_CRON_MINUTE_UTC,
        ),
        # 登録済みユーザー（GITHUB_USERNAME以外）向けDEPSCAN/CODESCAN/DEPSOPS（Issue #227）:
        # 削除済みリポジトリの掃除の後段に配置
        ScheduledJob(
            "user_crawl", "USER_CRAWL", run_user_crawls_for_all_accounts,
            settings.USER_CRAWL_CRON_HOUR_UTC, settings.USER_CRAWL_CRON_MINUTE_UTC,
        ),
        # MCPトークンの期限前通知（Slack）: 登録ユーザー向けクロールの後段に配置
        ScheduledJob(
            "mcp_token_expiry_notice", "MCP_EXPIRY_NOTICE", run_mcp_token_expiry_notices,
            settings.MCP_EXPIRY_NOTICE_CRON_HOUR_UTC, settings.MCP_EXPIRY_NOTICE_CRON_MINUTE_UTC,
        ),
        # 使われない OAuth 接続・登録の自動整理: 期限前通知の後段に配置
        ScheduledJob(
            "oauth_cleanup", "OAUTH_CLEANUP", run_oauth_cleanup,
            settings.OAUTH_CLEANUP_CRON_HOUR_UTC, settings.OAUTH_CLEANUP_CRON_MINUTE_UTC,
        ),
        # 公開サイトの外形監視（Issue #401）
        ScheduledJob(
            "site_monitor", "EXTMON", fetch_and_monitor_sites,
            settings.EXTMON_CRON_HOUR_UTC, settings.EXTMON_CRON_MINUTE_UTC,
        ),
        # リポジトリの設定の監査（Issue #398）
        ScheduledJob(
            "repo_audit", "REPOAUDIT", fetch_and_audit_repos,
            settings.REPOAUDIT_CRON_HOUR_UTC, settings.REPOAUDIT_CRON_MINUTE_UTC,
        ),
        # GitHub のセキュリティアラートの取り込み（Issue #402）
        ScheduledJob(
            "github_alerts", "GHALERT", fetch_and_store_github_alerts,
            settings.GHALERT_CRON_HOUR_UTC, settings.GHALERT_CRON_MINUTE_UTC,
        ),
        # 例外（受容など）の期限切れ・修正版の公開の確認と通知（Issue #403）: DEPSCAN・CODESCAN の後
        ScheduledJob(
            "exception_lifecycle", "EXCEPTION_LIFECYCLE", run_exception_lifecycle,
            settings.EXCEPTION_CRON_HOUR_UTC, settings.EXCEPTION_CRON_MINUTE_UTC,
        ),
        # 脆弱性への対応状況（期限超過・MTTR）の週次のまとめ（Issue #404）: 毎週月曜。
        # 前日までの DEPSCAN の結果を集計するため、毎日のジョブとは別の時刻に置く
        ScheduledJob(
            "sla_digest", "SLA_DIGEST", run_sla_digest,
            settings.SLA_DIGEST_CRON_HOUR_UTC, settings.SLA_DIGEST_CRON_MINUTE_UTC,
            day_of_week=settings.SLA_DIGEST_DAY_OF_WEEK,
        ),
    ]


def register_jobs(job_scheduler: BackgroundScheduler, jobs: list[ScheduledJob]) -> None:
    """ジョブを cron トリガーで登録し、スケジューラを起動する。"""
    for job in jobs:
        job_scheduler.add_job(
            job.func,
            trigger="cron",
            hour=job.hour,
            minute=job.minute,
            day_of_week=job.day_of_week,
            id=job.job_id,
            replace_existing=True,
        )
    job_scheduler.start()
    logger.info(
        "Scheduler started: %s",
        " / ".join(
            f"{job.label} UTC {job.hour:02d}:{job.minute:02d}"
            + (f" ({job.day_of_week})" if job.day_of_week else "")
            for job in jobs
        ),
    )
