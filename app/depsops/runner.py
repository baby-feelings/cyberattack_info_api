"""DEPSOPS（Dependabot PR 自動運用）モジュール。

DEPSCAN 対象の全リポジトリを走査し、Dependabot が作成した Open な PR を
安全性の高いもの（マイナー/パッチ更新・CI 設定あり・コンフリクトなし）に限って
自動マージする。それ以外（メジャーバージョンアップ・CI 未設定・CI 失敗・
判定不能）は自動マージせず Slack に通知して人の判断に委ねる。
コンフリクトで自動マージできない PR には `@dependabot rebase` を依頼する。

`/admin/dependabot-ops`（手動トリガーのみ・スケジューラ登録なし）から呼び出す。

判定結果（自動マージ・要確認）は Slack 通知に加え、`DependabotPrLog` テーブルにも
1 PR 1 行で永続化する。Slack 通知は実行時点のスナップショットのみで履歴を持たない
（ダッシュボードに表示する「要確認」PR の理由・件数は、この履歴 DB を参照する）。
"""
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.notifications import notify_dependabot_ops, notify_error
from app.crawler_logs.writer import now_utc, write_crawler_log
from app.depscan.github_client import list_target_repos
from app.depsops.classify import classify_bump
from app.depsops.github_client import (
    get_pull_request,
    has_ci_workflows,
    list_open_dependabot_alerts,
    list_open_dependabot_prs,
    merge_pull_request,
    request_rebase,
)
from app.depsops.models import DependabotPrLog

logger = logging.getLogger(__name__)


def _matches_security_alert(title: str, alert_package_names: set[str] | None) -> bool | None:
    """PRタイトルが、Open な Dependabot alert のいずれかの対象パッケージ名を
    含んでいるかをヒューリスティックに判定する。

    Returns:
        True: 一致する alert あり（セキュリティ更新の可能性が高い）
        False: alert 取得は成功したが一致なし（通常のバージョン更新）
        None: alert 自体を取得できなかった（判定不能。GITHUB_TOKEN に
            Dependabot alerts: Read-only 権限が無い場合等）

    Note:
        パッケージ名の単純な部分文字列一致（単語境界のみ考慮）のため、
        あるパッケージ名が別のパッケージ名の接頭辞になっているケース等で
        誤判定しうる（あくまで参考情報。判定基準は GitHub の Dependabot alert
        そのものであり、この関数は照合のヒューリスティックに過ぎない）。
    """
    if alert_package_names is None:
        return None
    lowered_title = title.lower()
    return any(
        re.search(rf"\b{re.escape(pkg.lower())}\b", lowered_title)
        for pkg in alert_package_names
    )


def _pr_summary(
    full_name: str, pr: dict[str, Any], is_security_update: bool | None,
) -> dict[str, Any]:
    return {
        "repo_full_name": full_name,
        "pr_number": pr["number"],
        "title": pr["title"],
        "is_security_update": is_security_update,
    }


def _process_pr(
    full_name: str, owner: str, repo: str, pr: dict[str, Any], has_ci: bool, token: str,
    alert_package_names: set[str] | None = None,
) -> tuple[str, dict[str, Any] | None]:
    """1件の PR を判定・処理する。

    Args:
        alert_package_names: 対象リポジトリの Open な Dependabot alert の
            パッケージ名集合（`_matches_security_alert` 参照）。取得できな
            かった場合は None。

    Returns:
        (action, item) のタプル。action は "merged" / "flagged" / "skipped"。
        "merged"/"flagged" の場合 item は Slack 通知用の辞書（"flagged" のみ "reason" 付き）。
    """
    number = pr["number"]
    bump = classify_bump(pr["title"])
    is_security_update = _matches_security_alert(pr["title"], alert_package_names)

    detail = get_pull_request(owner, repo, number, token)
    mergeable_state = detail.get("mergeable_state")

    if mergeable_state == "dirty":
        request_rebase(owner, repo, number, token)
        item = _pr_summary(full_name, pr, is_security_update)
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
        item = _pr_summary(full_name, pr, is_security_update)
        item["reason"] = reason
        return "flagged", item

    merge_pull_request(owner, repo, number, token)
    return "merged", _pr_summary(full_name, pr, is_security_update)


def _record_pr_logs(
    db: Session,
    merged: list[dict[str, Any]],
    flagged: list[dict[str, Any]],
    processed_at: datetime,
) -> None:
    """判定した PR を1件1行で DependabotPrLog に記録する。

    ダッシュボードで「要確認」PR の一覧・理由を後から確認できるようにするための
    履歴テーブル。Slack 通知（実行時点のスナップショットのみ）とは別に保持する。
    """
    for item in merged:
        db.add(DependabotPrLog(
            repo_full_name=item["repo_full_name"],
            pr_number=item["pr_number"],
            title=item["title"],
            action="merged",
            reason=None,
            is_security_update=item.get("is_security_update"),
            processed_at=processed_at,
        ))
    for item in flagged:
        db.add(DependabotPrLog(
            repo_full_name=item["repo_full_name"],
            pr_number=item["pr_number"],
            title=item["title"],
            action="flagged",
            reason=item.get("reason"),
            is_security_update=item.get("is_security_update"),
            processed_at=processed_at,
        ))
    db.commit()


def _delete_old_depsops_records(db: Session) -> int:
    """保持期間（DEPSOPS_RETENTION_DAYS）を超えた PR 履歴レコードを削除する。

    Returns:
        削除件数
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.DEPSOPS_RETENTION_DAYS)
    deleted = (
        db.query(DependabotPrLog)
        .filter(DependabotPrLog.processed_at < cutoff)
        .delete(synchronize_session=False)
    )
    db.commit()
    logger.info(
        "DEPSOPS old PR log records deleted: %d (processed_at < %s)", deleted, cutoff.date(),
    )
    return deleted


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

            # セキュリティ更新かどうかの判定用に、リポジトリ単位で1回だけ取得し使い回す。
            # 権限不足（GITHUB_TOKEN に Dependabot alerts: Read-only が無い）等で
            # 失敗しても DEPSOPS 本来のマージ判定は継続する（判定不能 = None のまま）
            alert_package_names: set[str] | None
            try:
                alerts = list_open_dependabot_alerts(owner, repo, settings.GITHUB_TOKEN)
                alert_package_names = {a["dependency"]["package"]["name"] for a in alerts}
            except httpx.HTTPError as exc:
                logger.warning(
                    "DEPSOPS: failed to list Dependabot alerts for %s: %s", full_name, exc,
                )
                alert_package_names = None

            for pr in prs:
                try:
                    action, item = _process_pr(
                        full_name, owner, repo, pr, has_ci, settings.GITHUB_TOKEN,
                        alert_package_names,
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

    # 判定履歴を DB に記録（ダッシュボードでの一覧表示用）。失敗してもクロール自体は成功扱いとする
    try:
        db: Session = SessionLocal()
        try:
            _record_pr_logs(db, merged, flagged, started_at)
            _delete_old_depsops_records(db)
        finally:
            db.close()
    except Exception as exc:
        logger.error("Failed to record DEPSOPS PR logs: %s", exc, exc_info=True)

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
