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
from app.codescan.crawler import SCAN_ERRORS, scan_repo
from app.codescan.issue_management import file_github_issues
from app.codescan.repository import CodeFindingRepository
from app.core.database import SessionLocal
from app.core.github.accounts import list_target_repos
from app.core.notifications.crawler import notify_success

logger = logging.getLogger(__name__)


def run_codescan_for_user(username: str, token: str) -> None:
    """GitHub ログインしたユーザー自身のリポジトリを CODESCAN でスキャンする。

    `app.jobs.user_crawl_runner`（登録済み他ユーザーの定期実行）から呼ばれる。
    """
    logger.info("=== CODESCAN (for %s) started ===", username)
    db: Session = SessionLocal()
    repository = CodeFindingRepository(db)
    new_count = 0
    all_new_snapshots: list[dict[str, Any]] = []
    try:
        repos = list_target_repos(token)
        logger.info("CODESCAN (for %s): %d target repos to scan", username, len(repos))

        for repo_info in repos:
            full_name = repo_info["full_name"]
            default_branch = repo_info.get("default_branch") or "main"
            try:
                records = scan_repo(full_name, default_branch, token)
            except SCAN_ERRORS as exc:
                logger.warning(
                    "CODESCAN (for %s): failed to scan %s, skipping: %s",
                    username, full_name, exc,
                )
                continue

            result = repository.sync(full_name, records)
            new_count += result.inserted
            all_new_snapshots.extend(result.new_snapshots)

        webhook = get_webhook_for_user(db, username)
        if webhook:
            notify_success("CODESCAN", inserted=new_count, updated=0, recipients=[webhook])
            try:
                file_github_issues(all_new_snapshots, token)
            except Exception as exc:
                logger.error(
                    "CODESCAN (for %s): failed to file GitHub issues: %s",
                    username, exc, exc_info=True,
                )

        logger.info(
            "=== CODESCAN (for %s) completed: repos=%d, new=%d ===",
            username, len(repos), new_count,
        )
    except Exception as exc:
        logger.error("CODESCAN (for %s) failed: %s", username, exc, exc_info=True)
    finally:
        db.close()
