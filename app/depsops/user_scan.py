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
from app.core.notifications import notify_dependabot_ops
from app.crawler_logs.writer import now_utc
from app.depscan.github_client import list_target_repos
from app.depsops.runner import _delete_old_depsops_records, _record_pr_logs, _scan_target_repos

logger = logging.getLogger(__name__)


def run_dependabot_ops_for_user(username: str, token: str, webhook_url: str) -> None:
    """登録済みユーザー自身のリポジトリを対象に DEPSOPS（安全な Dependabot PR の
    自動マージ）を実行し、結果を本人の Webhook にのみ通知する。
    """
    logger.info("=== DEPSOPS (for %s) started ===", username)
    db: Session = SessionLocal()
    try:
        repos = list_target_repos(username, token)
        logger.info("DEPSOPS (for %s): %d target repos to scan", username, len(repos))

        merged, flagged, resolved, error_count = _scan_target_repos(db, repos, token)

        try:
            processed_at_repos: list[dict[str, Any]] = merged + flagged + resolved
            if processed_at_repos:
                _record_pr_logs(db, merged, flagged, now_utc(), resolved=resolved)
                _delete_old_depsops_records(db)
        except Exception as exc:
            logger.error(
                "DEPSOPS (for %s): failed to record PR logs: %s", username, exc, exc_info=True,
            )

        notify_dependabot_ops(merged, flagged, recipients=[webhook_url])
        logger.info(
            "=== DEPSOPS (for %s) completed: merged=%d, flagged=%d, resolved=%d, errors=%d ===",
            username, len(merged), len(flagged), len(resolved), error_count,
        )
    except Exception as exc:
        logger.error("DEPSOPS (for %s) failed: %s", username, exc, exc_info=True)
    finally:
        db.close()
