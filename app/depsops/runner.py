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
from app.core.crawler_runner import CrawlCounters, CrawlJob
from app.core.notifications import notify_dependabot_ops
from app.crawler_logs.writer import now_utc
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


_COMPATIBILITY_BADGE_PATTERN = re.compile(
    r"!\[Dependabot compatibility score\]\((https://dependabot-badges\.githubapp\.com/[^)\s]+)\)",
)


def _extract_compatibility_badge_url(body: str | None) -> str | None:
    """PR本文から Dependabot の Compatibility score バッジ画像URLを抽出する。

    exact version bump のPR（"Bump X from A to B"）にのみ Dependabot が
    埋め込む（範囲指定の requirement 更新PR等には存在しない）。
    """
    if not body:
        return None
    match = _COMPATIBILITY_BADGE_PATTERN.search(body)
    return match.group(1) if match else None


def _pr_summary(
    full_name: str, pr: dict[str, Any], is_security_update: bool | None,
    compatibility_badge_url: str | None = None,
) -> dict[str, Any]:
    return {
        "repo_full_name": full_name,
        "pr_number": pr["number"],
        "title": pr["title"],
        "is_security_update": is_security_update,
        "compatibility_badge_url": compatibility_badge_url,
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
    compatibility_badge_url = _extract_compatibility_badge_url(detail.get("body"))

    if mergeable_state == "dirty":
        request_rebase(owner, repo, number, token)
        item = _pr_summary(full_name, pr, is_security_update, compatibility_badge_url)
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
        item = _pr_summary(full_name, pr, is_security_update, compatibility_badge_url)
        item["reason"] = reason
        return "flagged", item

    merge_pull_request(owner, repo, number, token)
    return "merged", _pr_summary(full_name, pr, is_security_update, compatibility_badge_url)


def record_pr_logs(
    db: Session,
    merged: list[dict[str, Any]],
    flagged: list[dict[str, Any]],
    processed_at: datetime,
    resolved: list[dict[str, Any]] | None = None,
) -> None:
    """判定した PR を1件1行で DependabotPrLog に記録し、解決済みPRの履歴を削除する。

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
            compatibility_badge_url=item.get("compatibility_badge_url"),
            processed_at=processed_at,
        ))
    for item in flagged:
        # 同じ理由で「要確認」のまま続くPRは毎日行を追記せず、既存行の判定日時を更新する
        # （理由・セキュリティ判定が変わった場合のみ新しい行として履歴に残す）
        latest = (
            db.query(DependabotPrLog)
            .filter(
                DependabotPrLog.repo_full_name == item["repo_full_name"],
                DependabotPrLog.pr_number == item["pr_number"],
            )
            .order_by(DependabotPrLog.processed_at.desc(), DependabotPrLog.id.desc())
            .first()
        )
        if (
            latest is not None
            and latest.action == "flagged"
            and latest.reason == item.get("reason")
            and latest.is_security_update == item.get("is_security_update")
        ):
            latest.title = item["title"]
            latest.compatibility_badge_url = item.get("compatibility_badge_url")
            latest.processed_at = processed_at
            continue
        db.add(DependabotPrLog(
            repo_full_name=item["repo_full_name"],
            pr_number=item["pr_number"],
            title=item["title"],
            action="flagged",
            reason=item.get("reason"),
            is_security_update=item.get("is_security_update"),
            compatibility_badge_url=item.get("compatibility_badge_url"),
            processed_at=processed_at,
        ))
    # 解決済み（DEPSOPS外の要因で解消）のPRは履歴を残さず、そのPRの全行を削除する。
    # 「未解決」件数は最新状態が"flagged"のPRのみを数えるため集計は変わらず、
    # 毎日追記される"flagged"行の肥大化も解消できる（自動マージ"merged"の記録は残す）
    for item in resolved or []:
        db.query(DependabotPrLog).filter(
            DependabotPrLog.repo_full_name == item["repo_full_name"],
            DependabotPrLog.pr_number == item["pr_number"],
        ).delete(synchronize_session=False)
    db.commit()


def _find_resolved_flagged_prs(
    db: Session, full_name: str, open_pr_numbers: set[int],
) -> list[dict[str, Any]]:
    """当該リポジトリで直近の判定が "flagged"（要確認）のまま記録されているが、
    今回のスキャンで Open な Dependabot PR 一覧に含まれなくなった PR を検出する。

    Dependabot自身による自動クローズ（後続のgrouped PRに統合される等）や、
    人手によるマージ・クローズなど、DEPSOPSの関知しないところで PR が解消される
    ケースがある。これを検知して"closed"として記録しないと、ダッシュボードの
    「未解決」件数（最新状態が"flagged"のPR数）が実態と乖離したまま残り続ける
    （典型例: CI未設定のリポジトリでは全PRが機械的にflaggedになるため、後から
    手動マージやDependabotの自動クローズで解消されても「未解決」表示が減らない）。
    """
    rows = (
        db.query(DependabotPrLog)
        .filter(DependabotPrLog.repo_full_name == full_name)
        .order_by(DependabotPrLog.processed_at.desc())
        .all()
    )
    latest_by_pr: dict[int, DependabotPrLog] = {}
    for row in rows:
        latest_by_pr.setdefault(row.pr_number, row)

    return [
        {
            "repo_full_name": full_name,
            "pr_number": row.pr_number,
            "title": row.title,
            "is_security_update": row.is_security_update,
            "compatibility_badge_url": row.compatibility_badge_url,
            "reason": "Dependabotの自動クローズや手動マージ等、DEPSOPS外の要因で解消済み",
        }
        for pr_number, row in latest_by_pr.items()
        if row.action == "flagged" and pr_number not in open_pr_numbers
    ]


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


def _purge_legacy_closed_pr_logs(db: Session) -> int:
    """過去に"closed"として記録されたPRの履歴行を全削除する（解決済みの削除方針への移行用）。

    以前は解消を検知すると"closed"行を追記していたが、現在は解消PRの全行を削除する。
    既に記録されている"closed"行を毎回の実行時に掃除し、マイグレーション無しで
    本番データを新方針へ収束させる。最新状態が"closed"のPRのみが対象で、
    その後再び"flagged"/"merged"になったPRは削除しない。

    Returns:
        削除した行数
    """
    rows = (
        db.query(
            DependabotPrLog.id, DependabotPrLog.repo_full_name,
            DependabotPrLog.pr_number, DependabotPrLog.action,
        )
        .order_by(DependabotPrLog.processed_at.desc(), DependabotPrLog.id.desc())
        .all()
    )
    latest: dict[tuple[str, int], str] = {}
    for _id, repo, number, action in rows:
        latest.setdefault((repo, number), action)

    deleted = 0
    for (repo, number), action in latest.items():
        if action != "closed":
            continue
        deleted += (
            db.query(DependabotPrLog)
            .filter(
                DependabotPrLog.repo_full_name == repo,
                DependabotPrLog.pr_number == number,
            )
            .delete(synchronize_session=False)
        )
    db.commit()
    logger.info("DEPSOPS legacy closed PR log records deleted: %d", deleted)
    return deleted


def _collapse_duplicate_flagged_logs(db: Session) -> int:
    """同一PRで同じ内容の"flagged"行が連続している重複を、最新の1行にまとめる。

    以前は「要確認」のPRが毎回の実行で1行ずつ追記されていたため、既存データには
    同じPRの同一内容の行が大量に残っている。直前の行（action問わず）と
    (action="flagged", reason, is_security_update)が同一の"flagged"行について、
    古い側を削除して最新の行だけを残す（冪等）。

    Returns:
        削除した行数
    """
    rows = (
        db.query(DependabotPrLog)
        .order_by(
            DependabotPrLog.repo_full_name, DependabotPrLog.pr_number,
            DependabotPrLog.processed_at.asc(), DependabotPrLog.id.asc(),
        )
        .all()
    )
    delete_ids: list[int] = []
    previous: DependabotPrLog | None = None
    for row in rows:
        same_pr = (
            previous is not None
            and previous.repo_full_name == row.repo_full_name
            and previous.pr_number == row.pr_number
        )
        if (
            same_pr
            and previous is not None
            and previous.action == "flagged"
            and row.action == "flagged"
            and previous.reason == row.reason
            and previous.is_security_update == row.is_security_update
        ):
            delete_ids.append(previous.id)
        previous = row

    for start in range(0, len(delete_ids), 500):
        db.query(DependabotPrLog).filter(
            DependabotPrLog.id.in_(delete_ids[start:start + 500])
        ).delete(synchronize_session=False)
    db.commit()
    logger.info("DEPSOPS duplicate flagged log records collapsed: %d", len(delete_ids))
    return len(delete_ids)


def cleanup_pr_logs(db: Session) -> None:
    """PR判定履歴の整理（旧"closed"行の削除・重複"flagged"行の集約・保持期間超過分の削除）。"""
    _purge_legacy_closed_pr_logs(db)
    _collapse_duplicate_flagged_logs(db)
    _delete_old_depsops_records(db)


def _process_repo(
    db: Session, full_name: str, token: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], int]:
    """1リポジトリ分の Open な Dependabot PR を取得・判定する。

    run_dependabot_ops のリポジトリループ本体（PR取得・解消済みflagged検知・
    CI有無判定・Dependabot alert取得・各PRの判定）を1リポジトリ単位に切り出したもの。

    Args:
        token: 省略時は`settings.GITHUB_TOKEN`（baby-feelings向け毎日クロールの
            既定）。登録済み他ユーザー自身のリポジトリに対して実行する場合
            （Issue #227）は、そのユーザー自身のOAuthアクセストークンを渡す。

    Returns:
        (merged, flagged, resolved, error_count) のタプル。
        PRリスト取得・個別PR処理のHTTPErrorはこのリポジトリ単位で握りつぶし、
        error_countとしてカウントする（他リポジトリの処理は継続する既存挙動を維持）。
    """
    token = token if token is not None else settings.GITHUB_TOKEN
    owner, repo = full_name.split("/", 1)
    merged: list[dict[str, Any]] = []
    flagged: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    error_count = 0

    try:
        prs = list_open_dependabot_prs(owner, repo, token)
    except httpx.HTTPError as exc:
        logger.warning("DEPSOPS: failed to list PRs for %s: %s", full_name, exc)
        return merged, flagged, resolved, error_count + 1

    # Open PR一覧が取得できた時点で、過去にflagged記録したPRが
    # DEPSOPS外の要因で解消済みでないかを毎回チェックする（PRの有無に関わらず）
    resolved.extend(_find_resolved_flagged_prs(
        db, full_name, {pr["number"] for pr in prs},
    ))

    if not prs:
        return merged, flagged, resolved, error_count

    has_ci = has_ci_workflows(owner, repo, token)
    logger.info(
        "DEPSOPS: %s has %d open Dependabot PR(s), CI=%s",
        full_name, len(prs), has_ci,
    )

    # セキュリティ更新かどうかの判定用に、リポジトリ単位で1回だけ取得し使い回す。
    # 権限不足（GITHUB_TOKEN に Dependabot alerts: Read-only が無い）等で
    # 失敗しても DEPSOPS 本来のマージ判定は継続する（判定不能 = None のまま）
    alert_package_names: set[str] | None
    try:
        alerts = list_open_dependabot_alerts(owner, repo, token)
        alert_package_names = {a["dependency"]["package"]["name"] for a in alerts}
    except httpx.HTTPError as exc:
        logger.warning(
            "DEPSOPS: failed to list Dependabot alerts for %s: %s", full_name, exc,
        )
        alert_package_names = None

    for pr in prs:
        try:
            action, item = _process_pr(
                full_name, owner, repo, pr, has_ci, token,
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

    return merged, flagged, resolved, error_count


def scan_target_repos(
    db: Session, repos: list[dict[str, Any]], token: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], int]:
    """対象リポジトリ全件を走査し、判定結果を集約する。"""
    merged: list[dict[str, Any]] = []
    flagged: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    error_count = 0

    for repo_info in repos:
        repo_merged, repo_flagged, repo_resolved, repo_errors = _process_repo(
            db, repo_info["full_name"], token,
        )
        merged.extend(repo_merged)
        flagged.extend(repo_flagged)
        resolved.extend(repo_resolved)
        error_count += repo_errors

    return merged, flagged, resolved, error_count


class _DepsopsJob(CrawlJob):
    """DEPSOPS の1回分の実行（`CrawlJob` のサブクラス）。

    `CrawlCounters` へのマッピング: inserted=自動マージ件数、updated=要確認件数、
    deleted=解消済みと判定した件数。戻り値は (自動マージ, 要確認, エラー数)。
    リポジトリ単位の失敗（error_count）はクロール全体を失敗扱いにしない。
    """

    crawler_type = "DEPSOPS"

    def __init__(self) -> None:
        self.merged: list[dict[str, Any]] = []
        self.flagged: list[dict[str, Any]] = []
        self.error_count = 0

    def execute(self, db: Session, counters: CrawlCounters) -> None:
        started_at = now_utc()
        repos = list_target_repos(settings.GITHUB_USERNAME, settings.GITHUB_TOKEN)
        logger.info("DEPSOPS: %d target repos to scan", len(repos))

        self.merged, self.flagged, resolved, self.error_count = scan_target_repos(db, repos)
        counters.inserted = len(self.merged)
        counters.updated = len(self.flagged)
        counters.deleted = len(resolved)

        # 判定履歴を DB に記録（ダッシュボードでの一覧表示用）。
        # 失敗してもクロール自体は成功扱いとする
        try:
            record_pr_logs(db, self.merged, self.flagged, started_at, resolved=resolved)
            cleanup_pr_logs(db)
        except Exception as exc:
            logger.error("Failed to record DEPSOPS PR logs: %s", exc, exc_info=True)

    def after_success(self, counters: CrawlCounters) -> None:
        logger.info(
            "=== DEPSOPS completed: merged=%d, flagged=%d, resolved=%d, errors=%d ===",
            counters.inserted, counters.updated, counters.deleted, self.error_count,
        )
        notify_dependabot_ops(self.merged, self.flagged)

    def result(self, counters: CrawlCounters) -> tuple[int, ...]:
        return counters.inserted, counters.updated, self.error_count


def run_dependabot_ops(*, force: bool = False) -> tuple[int, int, int]:
    """DEPSOPS のメインエントリポイント。

    Args:
        force: True の場合、今日すでに成功実行済みでも強制的に再実行する（Issue #239）。
            DEPSOPSは判定履歴を実行ごとに記録する設計のため、二重実行が
            そのまま件数の二重化に直結する（本番で総件数2388件中約半数が重複だった）。

    Returns:
        (merged_count, flagged_count, error_count) のタプル（スキップ時は (0, 0, 0)）
    """
    logger.info("=== DEPSOPS started ===")
    return _DepsopsJob().run(force=force)  # type: ignore[return-value]
