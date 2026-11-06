"""登録済みユーザー自身のリポジトリに対する DEPSOPS 実行モジュール（Issue #227）。

`app.depsops.runner.run_dependabot_ops`（baby-feelings 向けの毎日の定期実行）とは
独立した経路。本人が Slack Webhook を登録して通知を有効にしている場合のみ実行・
通知する（未登録ユーザーのリポジトリを勝手にマージ操作しないため、`app.core
.user_crawl_runner` 側で登録済みユーザーのみを対象にループする前提の関数）。

DependabotPrLog への記録は baby-feelings 向けと同じテーブルを共有する
（`repo_full_name` にオーナー名を含むため、ダッシュボードでの表示上の混同は
起きない。DRY原則によりテーブルを分けない）。
"""
import logging
from typing import Any

from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.core.db_utils import now_utc
from app.core.github.accounts import list_target_repos
from app.core.user_scan import UserScanJob
from app.depsops.notifier import notify_dependabot_ops
from app.depsops.pr_log_repository import PrLogRepository
from app.depsops.runner import scan_target_repos

logger = logging.getLogger(__name__)


class DependabotOpsUserScan(UserScanJob):
    """登録済みユーザー自身のリポジトリの DEPSOPS（安全な Dependabot PR の自動マージ）。"""

    source = "DEPSOPS"

    def __init__(self, username, token, session_factory, webhook_url: str):
        super().__init__(username, token, session_factory)
        self.webhook_url = webhook_url

    def execute(self, db: Session) -> None:
        repos = list_target_repos(self.token)
        logger.info("%s: %d target repos to scan", self.tag, len(repos))

        merged, flagged, resolved, error_count = scan_target_repos(db, repos, self.token)

        with self.guard("record PR logs"):
            processed_at_repos: list[dict[str, Any]] = merged + flagged + resolved
            if processed_at_repos:
                repository = PrLogRepository(db)
                repository.record(merged, flagged, now_utc(), resolved=resolved)
                repository.cleanup()

        notify_dependabot_ops(merged, flagged, recipients=[self.webhook_url])
        logger.info(
            "=== %s completed: merged=%d, flagged=%d, resolved=%d, errors=%d ===",
            self.tag, len(merged), len(flagged), len(resolved), error_count,
        )


def run_dependabot_ops_for_user(username: str, token: str, webhook_url: str) -> None:
    """登録済みユーザー自身のリポジトリを対象に DEPSOPS（安全な Dependabot PR の
    自動マージ）を実行し、結果を本人の Webhook にのみ通知する。
    """
    DependabotOpsUserScan(username, token, SessionLocal, webhook_url).run()
