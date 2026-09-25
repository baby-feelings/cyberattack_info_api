"""登録済みユーザー自身のリポジトリに対するオンデマンド／定期 CODESCAN スキャン
モジュール（Issue #227）。

`app.codescan.crawler.fetch_and_scan_code`（baby-feelings 向けの毎日の定期実行）
とは独立した経路。DEPSCAN の `app.depscan.user_scan.run_depscan_for_user` と同じ
設計方針: 通知・GitHub Issue起票は、本人が Slack Webhook を登録して通知を
有効にしている場合のみ行う（未登録ユーザーには一切通知しない）。
CODESCAN には DEPSCAN のようなオンデマンドスキャン進捗ポーリングUIが無いため、
`UserScan` 相当の進捗テーブルは持たない（ログのみ）。
"""
import json
import logging
import subprocess
import tarfile
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.auth.account_store import get_webhook_for_user
from app.codescan.crawler import (
    FindingKey,
    _resolve_stale_repo_findings,
    _scan_repo,
    _upsert_repo_findings,
)
from app.codescan.issue_management import _file_github_issues
from app.core.database import SessionLocal
from app.core.notifications import notify_success
from app.depscan.github_client import list_target_repos

logger = logging.getLogger(__name__)


def run_codescan_for_user(username: str, token: str) -> None:
    """GitHub ログインしたユーザー自身のリポジトリを CODESCAN でスキャンする。

    `app.core.user_crawl_runner`（登録済み他ユーザーの定期実行）から呼ばれる。
    """
    logger.info("=== CODESCAN (for %s) started ===", username)
    db: Session = SessionLocal()
    new_count = 0
    all_new_snapshots: list[dict[str, Any]] = []
    try:
        repos = list_target_repos(username, token)
        logger.info("CODESCAN (for %s): %d target repos to scan", username, len(repos))

        for repo_info in repos:
            full_name = repo_info["full_name"]
            default_branch = repo_info.get("default_branch") or "main"
            try:
                records = _scan_repo(full_name, default_branch, token)
            except (httpx.HTTPError, subprocess.TimeoutExpired, tarfile.TarError,
                     json.JSONDecodeError, OSError) as exc:
                logger.warning(
                    "CODESCAN (for %s): failed to scan %s, skipping: %s",
                    username, full_name, exc,
                )
                continue

            inserted, new_snapshots = _upsert_repo_findings(db, full_name, records)
            new_count += inserted
            all_new_snapshots.extend(new_snapshots)

            current_keys: set[FindingKey] = {
                (r["repo_full_name"], r["file_path"], r["rule_id"], r["line_start"])
                for r in records
            }
            _resolve_stale_repo_findings(db, full_name, current_keys)

        webhook = get_webhook_for_user(db, username)
        if webhook:
            notify_success("CODESCAN", inserted=new_count, updated=0, recipients=[webhook])
            try:
                _file_github_issues(all_new_snapshots, token)
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
