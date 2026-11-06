"""登録済みユーザー自身のリポジトリに対するオンデマンド／定期 CODESCAN スキャン
モジュール（Issue #227）。

`app.codescan.crawler.fetch_and_scan_code`（baby-feelings 向けの毎日の定期実行）
とは独立した経路。DEPSCAN の `app.depscan.user_scan.run_depscan_for_user` と同じ
設計方針: 通知・GitHub Issue起票は、本人が Slack Webhook を登録して通知を
有効にしている場合のみ行う（未登録ユーザーには一切通知しない）。
CODESCAN には DEPSCAN のようなオンデマンドスキャン進捗ポーリングUIが無いため、
`UserScan` 相当の進捗テーブルは持たない（ログのみ）。
"""
import logging
from typing import Any

from sqlalchemy.orm import Session

from app.auth.account_store import get_webhook_for_user
from app.codescan.crawler import SCAN_ERRORS, failed_tools_of, scan_repo
from app.codescan.issue_management import close_resolved_repo_issues, file_github_issues
from app.codescan.notifier import notify_code_findings
from app.codescan.repository import CodeFindingRepository
from app.core.database import SessionLocal
from app.core.github.accounts import list_target_repos
from app.core.user_scan import UserScanJob

logger = logging.getLogger(__name__)


class CodescanUserScan(UserScanJob):
    """ユーザー自身のリポジトリの CODESCAN。進捗テーブルは持たない（ログのみ）。"""

    source = "CODESCAN"

    def execute(self, db: Session) -> None:
        repository = CodeFindingRepository(db)
        new_count = 0
        all_new_snapshots: list[dict[str, Any]] = []
        # 全ツールの検査に成功したリポジトリ（Issue のクローズの判定の対象）
        fully_scanned: set[str] = set()

        repos = list_target_repos(self.token)
        logger.info("%s: %d target repos to scan", self.tag, len(repos))

        for repo_info in repos:
            full_name = repo_info["full_name"]
            default_branch = repo_info.get("default_branch") or "main"
            try:
                records = scan_repo(full_name, default_branch, self.token)
            except SCAN_ERRORS as exc:
                logger.warning("%s: failed to scan %s, skipping: %s", self.tag, full_name, exc)
                continue

            failed_tools = failed_tools_of(records)
            result = repository.sync(full_name, records, failed_tools)
            if not failed_tools:
                fully_scanned.add(full_name)
            new_count += result.inserted
            all_new_snapshots.extend(result.new_snapshots)

        webhook = get_webhook_for_user(db, self.username)
        if webhook:
            notify_code_findings(all_new_snapshots, recipients=[webhook])
            with self.guard("file GitHub issues"):
                file_github_issues(all_new_snapshots, self.token)
            with self.guard("close GitHub issues"):
                close_resolved_repo_issues(db, fully_scanned, self.token)

        logger.info(
            "=== %s completed: repos=%d, new=%d ===", self.tag, len(repos), new_count,
        )


def run_codescan_for_user(username: str, token: str) -> None:
    """GitHub ログインしたユーザー自身のリポジトリを CODESCAN でスキャンする。

    `app.jobs.user_crawl_runner`（登録済み他ユーザーの定期実行）から呼ばれる。
    """
    CodescanUserScan(username, token, SessionLocal).run()
