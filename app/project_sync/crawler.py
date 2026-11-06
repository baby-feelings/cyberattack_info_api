"""GitHub Projects への、Issue・PR の自動追加（PROJSYNC）のジョブの組み立て。

全対象リポジトリの Open の Issue・PR のうち、Project にまだ載っていないものを追加する。
GitHub の Project の組み込み「Auto-add」は、リポジトリごとの画面設定が要るため、本アプリが
毎日、同期する（新しいリポジトリも、自動で対象になる）。Issue・PR のクローズ・マージによる
「Done」への移動は、Project の組み込みの設定が行う（このジョブは、追加だけを行う）。

`PROJSYNC_NUMBER` が 0（既定）なら何もしない。トークンに `project` 権限が無いときは、
`ProjectScopeError` でジョブを失敗にする（失敗として記録・通知され、気づける）。
"""
import logging

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.github.accounts import list_target_repos
from app.core.github.api import GitHubApi
from app.core.github.repo import GitHubRepo
from app.core.runner.crawler_runner import CrawlCounters, CrawlJob
from app.project_sync.client import ProjectSyncError, add_item, fetch_project, list_open_items

logger = logging.getLogger(__name__)


class _ProjectSyncJob(CrawlJob):
    """PROJSYNC の1回分の実行。

    `CrawlCounters` へのマッピング: inserted=Project に追加した件数、
    updated=取得・追加に失敗した件数、deleted=未使用（0）。
    """

    crawler_type = "PROJSYNC"

    def __init__(self) -> None:
        self.repos_scanned = 0

    def execute(self, db: Session, counters: CrawlCounters) -> None:
        if settings.PROJSYNC_NUMBER <= 0:
            logger.info("PROJSYNC: disabled (PROJSYNC_NUMBER is not set)")
            return
        token = settings.GITHUB_TOKEN
        with GitHubApi(token) as api:
            project_id, existing = fetch_project(
                api, settings.GITHUB_USERNAME, settings.PROJSYNC_NUMBER,
            )
            repos = list_target_repos(token)
            self.repos_scanned = len(repos)
            for repo_info in repos:
                if counters.inserted >= settings.PROJSYNC_MAX_ADD:
                    logger.warning(
                        "PROJSYNC: reached the add limit (%d)", settings.PROJSYNC_MAX_ADD,
                    )
                    break
                self._sync_repo(api, project_id, existing, repo_info["full_name"], counters)

    def _sync_repo(
        self, api: GitHubApi, project_id: str, existing: set[str], full_name: str,
        counters: CrawlCounters,
    ) -> None:
        """1リポジトリ分を同期する。1件・1リポジトリの失敗で、他を止めない。"""
        try:
            items = list_open_items(GitHubRepo.from_full_name(full_name, settings.GITHUB_TOKEN))
        except httpx.HTTPError as exc:
            logger.warning("PROJSYNC: %s list failed: %s", full_name, exc)
            counters.updated += 1
            return
        for item in items:
            if item["node_id"] in existing:
                continue
            if counters.inserted >= settings.PROJSYNC_MAX_ADD:
                return
            try:
                add_item(api, project_id, item["node_id"])
            except (httpx.HTTPError, ProjectSyncError) as exc:
                logger.warning("PROJSYNC: add failed %s: %s", item["html_url"], exc)
                counters.updated += 1
                continue
            existing.add(item["node_id"])
            counters.inserted += 1

    def after_success(self, counters: CrawlCounters) -> None:
        logger.info(
            "=== PROJSYNC completed: added=%d, failed=%d, repos=%d ===",
            counters.inserted, counters.updated, self.repos_scanned,
        )

    def result(self, counters: CrawlCounters) -> tuple[int, ...]:
        return counters.inserted, counters.updated, self.repos_scanned


def sync_project_items(*, force: bool = False) -> tuple[int, int, int]:
    """PROJSYNC のメインエントリポイント。APScheduler から毎日呼び出される。

    Returns:
        (added, failed, repos) のタプル（スキップ時は (0, 0, 0)）
    """
    logger.info("=== PROJSYNC started ===")
    return _ProjectSyncJob().run(force=force)  # type: ignore[return-value]
