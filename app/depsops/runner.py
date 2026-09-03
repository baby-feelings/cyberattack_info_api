"""DEPSOPS（Dependabot PR 自動運用）モジュール。

DEPSCAN 対象の全リポジトリを走査し、Dependabot が作成した Open な PR を
安全性の高いもの（マイナー/パッチ更新・CI 設定あり・コンフリクトなし）に限って
自動マージする。それ以外（メジャーバージョンアップ・CI 未設定・CI 失敗・
判定不能）は自動マージせず Slack に通知して人の判断に委ねる。
コンフリクトで自動マージできない PR には `@dependabot rebase` を依頼する。

`/admin/dependabot-ops`（手動トリガーのみ・スケジューラ登録なし）から呼び出す。
"""
import logging
from typing import Any

import httpx

from app.core.config import settings
from app.core.notifications import notify_dependabot_ops, notify_error
from app.crawler_logs.writer import now_utc, write_crawler_log
from app.depscan.github_client import list_target_repos
from app.depsops.classify import classify_bump
from app.depsops.github_client import (
    get_pull_request,
    has_ci_workflows,
    list_open_dependabot_prs,
    merge_pull_request,
    request_rebase,
)

logger = logging.getLogger(__name__)


def _pr_summary(full_name: str, pr: dict[str, Any]) -> dict[str, Any]:
    return {
        "repo_full_name": full_name,
        "pr_number": pr["number"],
        "title": pr["title"],
    }


def _process_pr(
    full_name: str, owner: str, repo: str, pr: dict[str, Any], has_ci: bool, token: str,
) -> tuple[str, dict[str, Any] | None]:
    """1件の PR を判定・処理する。

    Returns:
        (action, item) のタプル。action は "merged" / "flagged" / "skipped"。
        "merged"/"flagged" の場合 item は Slack 通知用の辞書（"flagged" のみ "reason" 付き）。
    """
    number = pr["number"]
    bump = classify_bump(pr["title"])

    detail = get_pull_request(owner, repo, number, token)
    mergeable_state = detail.get("mergeable_state")

    if mergeable_state == "dirty":
        request_rebase(owner, repo, number, token)
        item = _pr_summary(full_name, pr)
        item["reason"] = "コンフリクトのためリベースを依頼"
        return "flagged", item

    reason = None
    if not has_ci:
        reason = "CI未設定のリポジトリ"
    elif bump == "major":
        reason = "メジャーバージョンアップ"
    elif bump == "unknown":
        reason = "バージョン判定不可（複数パッケージのグループ更新等）"
    elif mergeable_state != "clean":
        reason = f"マージ可否が不明確（mergeable_state={mergeable_state}）"

    if reason is not None:
        item = _pr_summary(full_name, pr)
        item["reason"] = reason
        return "flagged", item

    merge_pull_request(owner, repo, number, token)
    return "merged", _pr_summary(full_name, pr)


def run_dependabot_ops() -> tuple[int, int, int]:
    """DEPSOPS のメインエントリポイント。

    Returns:
        (merged_count, flagged_count, error_count) のタプル
    """
    logger.info("=== DEPSOPS started ===")
    started_at = now_utc()
    merged: list[dict[str, Any]] = []
    flagged: list[dict[str, Any]] = []
    error_count = 0

    try:
        repos = list_target_repos(settings.GITHUB_USERNAME, settings.GITHUB_TOKEN)
        logger.info("DEPSOPS: %d target repos to scan", len(repos))

        for repo_info in repos:
            full_name = repo_info["full_name"]
            owner, repo = full_name.split("/", 1)

            try:
                prs = list_open_dependabot_prs(owner, repo, settings.GITHUB_TOKEN)
            except httpx.HTTPError as exc:
                logger.warning("DEPSOPS: failed to list PRs for %s: %s", full_name, exc)
                error_count += 1
                continue

            if not prs:
                continue

            has_ci = has_ci_workflows(owner, repo, settings.GITHUB_TOKEN)
            logger.info(
                "DEPSOPS: %s has %d open Dependabot PR(s), CI=%s", full_name, len(prs), has_ci,
            )

            for pr in prs:
                try:
                    action, item = _process_pr(
                        full_name, owner, repo, pr, has_ci, settings.GITHUB_TOKEN,
                    )
                except httpx.HTTPError as exc:
                    logger.warning(
                        "DEPSOPS: failed to process %s#%d: %s", full_name, pr["number"], exc,
                    )
                    error_count += 1
                    continue

                if action == "merged" and item is not None:
                    merged.append(item)
                elif action == "flagged" and item is not None:
                    flagged.append(item)

    except Exception as exc:
        write_crawler_log(
            crawler_type="DEPSOPS",
            status="error",
            started_at=started_at,
            finished_at=now_utc(),
            inserted=len(merged),
            updated=len(flagged),
            deleted=0,
            error_message=str(exc),
        )
        notify_error("DEPSOPS", str(exc))
        raise

    logger.info(
        "=== DEPSOPS completed: merged=%d, flagged=%d, errors=%d ===",
        len(merged), len(flagged), error_count,
    )
    write_crawler_log(
        crawler_type="DEPSOPS",
        status="success",
        started_at=started_at,
        finished_at=now_utc(),
        inserted=len(merged),
        updated=len(flagged),
        deleted=0,
    )
    notify_dependabot_ops(merged, flagged)
    return len(merged), len(flagged), error_count
