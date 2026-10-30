"""GitHub のセキュリティアラートの取り込み（GHALERT）のジョブの組み立て（Issue #402）。

全対象リポジトリについて、secret scanning・Dependabot alerts・code scanning の
未解決のアラートを取得し、
保存する。機能が無効・権限不足（取得不可）のものは、既存のアラートに触らず、状態だけを記録する。
新規に見つかった secret scanning のアラートは、管理者に Slack で知らせる
（無効化・再発行の手順つき）。
毎日 APScheduler から呼ばれる（`app.jobs.scheduler_jobs`）。
"""
import logging
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.crawler_runner import CrawlCounters, CrawlJob
from app.core.github.accounts import list_target_repos
from app.core.github.repo import GitHubRepo
from app.core.notifications.github_alerts import GithubAlertNotifier
from app.finding_exceptions.matching import snapshot_of
from app.github_alerts.client import fetch_alerts
from app.github_alerts.models import KIND_SECRET, KINDS, GithubAlert
from app.github_alerts.repository import GithubAlertRepository

logger = logging.getLogger(__name__)


class _GithubAlertJob(CrawlJob):
    """GHALERT の1回分の実行。

    `CrawlCounters` へのマッピング: inserted=新規のアラート、deleted=解決済みにした件数、
    updated=取得できなかった（リポジトリ×種類の）数。
    """

    crawler_type = "GHALERT"

    def __init__(self) -> None:
        self.new_secret_snapshots: list[dict[str, Any]] = []
        self.repos_scanned = 0

    def execute(self, db: Session, counters: CrawlCounters) -> None:
        repos = list_target_repos(settings.GITHUB_TOKEN)
        self.repos_scanned = len(repos)
        repository = GithubAlertRepository(db)
        for repo_info in repos:
            repo = GitHubRepo.from_full_name(repo_info["full_name"], settings.GITHUB_TOKEN)
            for kind in KINDS:
                # 1リポジトリ・1種類の失敗で、他の取得を止めない
                try:
                    alerts, reason = fetch_alerts(repo, kind)
                except httpx.HTTPError as exc:
                    logger.warning("GHALERT: %s %s failed: %s", repo.full_name, kind, exc)
                    counters.updated += 1
                    continue
                if alerts is None:
                    repository.record_unavailable(kind, repo.full_name, reason or "")
                    counters.updated += 1
                    continue
                before = db.query(GithubAlert).filter(
                    GithubAlert.kind == kind, GithubAlert.repo_full_name == repo.full_name,
                    GithubAlert.resolved_at.is_(None),
                ).count()
                new = repository.sync(kind, repo.full_name, alerts)
                counters.inserted += len(new)
                counters.deleted += max(0, before + len(new) - len(alerts))
                if kind == KIND_SECRET and new:
                    self.new_secret_snapshots.extend(snapshot_of(a) for a in new)

    def after_success(self, counters: CrawlCounters) -> None:
        logger.info(
            "=== GHALERT completed: new=%d, resolved=%d, unavailable=%d, repos=%d ===",
            counters.inserted, counters.deleted, counters.updated, self.repos_scanned,
        )
        # 新規のシークレット漏えいだけを知らせる（他の種類は、一覧・比較で確認する）。通知の失敗で、
        # クロールを失敗にしない
        try:
            if GithubAlertNotifier(self.new_secret_snapshots).send():
                logger.info("GHALERT: notified %d secret alerts", len(self.new_secret_snapshots))
        except Exception as exc:
            logger.error("GHALERT: failed to notify: %s", exc, exc_info=True)

    def result(self, counters: CrawlCounters) -> tuple[int, ...]:
        return counters.inserted, counters.deleted, self.repos_scanned


def fetch_and_store_github_alerts(*, force: bool = False) -> tuple[int, int, int]:
    """GHALERT のメインエントリポイント。APScheduler から毎日呼び出される。

    Returns:
        (new, resolved, repos) のタプル（スキップ時は (0, 0, 0)）
    """
    logger.info("=== GHALERT started ===")
    return _GithubAlertJob().run(force=force)  # type: ignore[return-value]
