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
from app.core.repo_cleanup import run_repo_cleanup
from app.core.user_crawl_runner import run_user_crawls_for_all_accounts
from app.depscan.crawler import fetch_and_scan_dependencies
from app.depsops.runner import run_dependabot_ops
from app.jvn.crawler import fetch_and_store_jvn
from app.kev.crawler import fetch_and_store_kev
from app.osv.crawler import fetch_and_store_osv

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScheduledJob:
    """毎日1回の cron ジョブ（UTC の時・分で実行する）。"""

    job_id: str
    label: str
    func: Callable[..., Any]
    hour: int
    minute: int = 0


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
    ]


def register_jobs(job_scheduler: BackgroundScheduler, jobs: list[ScheduledJob]) -> None:
    """ジョブを cron トリガーで登録し、スケジューラを起動する。"""
    for job in jobs:
        job_scheduler.add_job(
            job.func,
            trigger="cron",
            hour=job.hour,
            minute=job.minute,
            id=job.job_id,
            replace_existing=True,
        )
    job_scheduler.start()
    logger.info(
        "Scheduler started: %s",
        " / ".join(f"{job.label} UTC {job.hour:02d}:{job.minute:02d}" for job in jobs),
    )
