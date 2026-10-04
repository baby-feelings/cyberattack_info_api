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
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.crawler_runner import CrawlCounters, CrawlJob
from app.core.notifications import notify_dependabot_ops
from app.crawler_logs.writer import now_utc
from app.depscan.github_client import list_target_repos
from app.depsops.github_client import (
    has_ci_workflows,
    list_open_dependabot_alerts,
    list_open_dependabot_prs,
)
from app.depsops.pr_judge import PrJudge
from app.depsops.pr_log_repository import PrLogRepository

logger = logging.getLogger(__name__)


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
    resolved.extend(PrLogRepository(db).find_resolved_flagged(
        full_name, {pr["number"] for pr in prs},
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

    judge = PrJudge(
        full_name, owner, repo, token, has_ci=has_ci, alert_package_names=alert_package_names,
    )
    for pr in prs:
        try:
            action, item = judge.judge(pr)
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
            repository = PrLogRepository(db)
            repository.record(self.merged, self.flagged, started_at, resolved=resolved)
            repository.cleanup()
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
