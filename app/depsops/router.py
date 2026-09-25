"""DEPSOPS（Dependabot PR 自動運用）API ルーター。

GET /api/depsops – 判定履歴一覧（自動マージ・要確認）。リポジトリ・action でフィルタ可能。
GET /api/depsops/stats – リポジトリ別の未解決PR件数（ダッシュボードの棒グラフ表示用）。
POST /admin/dependabot-ops – 手動トリガー（バックグラウンド）。
"""
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Security
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.auth import require_api_key, require_public_api_key
from app.core.background import run_in_background
from app.core.database import get_db
from app.core.pagination import paginate
from app.depsops.models import DependabotPrLog
from app.depsops.runner import run_dependabot_ops
from app.depsops.schemas import (
    DependabotPrLogListResponse,
    DependabotPrLogOut,
    DepsOpsStatsResponse,
    RepoStat,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/depsops",
    tags=["depsops"],
    dependencies=[Depends(require_public_api_key)],
)

# 管理者用エンドポイント（/admin/dependabot-ops）。prefix なし・require_api_key で保護する。
admin_router = APIRouter(tags=["admin"])


@admin_router.post(
    "/admin/dependabot-ops",
    dependencies=[Security(require_api_key)],
    summary="Dependabot PR 自動運用（手動トリガーのみ・バックグラウンド）",
    description="DEPSCAN 対象の全リポジトリの Open な Dependabot PR を判定し、"
    "マイナー/パッチ更新かつ CI 設定ありでコンフリクトが無いものだけ自動マージする"
    "（X-API-KEY 必須）。それ以外は Slack に通知するのみで自動マージしない。"
    "結果は /api/crawler-logs（crawler_type=DEPSOPS）および /api/depsops で確認。",
    status_code=202,
)
def trigger_dependabot_ops() -> dict:
    """Dependabot PR 自動運用（DEPSOPS）をバックグラウンドで実行する。"""
    logger.info("Manual DEPSOPS triggered via /admin/dependabot-ops")
    run_in_background("DEPSOPS", run_dependabot_ops)
    return {"message": "Dependabot PR operations started in background"}


@router.get(
    "",
    response_model=DependabotPrLogListResponse,
    summary="Dependabot PR 自動運用の判定履歴一覧取得",
    description="DEPSOPS が判定した Dependabot PR（自動マージ・要確認）の履歴を返す。"
    "リポジトリ・action（merged/flagged）でフィルタリング可能。",
)
def list_depsops(
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1, description="ページ番号（1始まり）"),
    per_page: int = Query(50, ge=1, le=200, description="1ページあたりの件数"),
    repo: str | None = Query(None, description="リポジトリ名絞り込み（例: owner/repo）"),
    action: str | None = Query(None, description="判定結果で絞り込み（merged / flagged）"),
) -> DependabotPrLogListResponse:
    """DEPSOPS の判定履歴（自動マージ・要確認）を取得する。直近の処理日時順。"""
    query = db.query(DependabotPrLog)

    if repo:
        query = query.filter(DependabotPrLog.repo_full_name == repo)
    if action:
        query = query.filter(DependabotPrLog.action == action)

    total, items = paginate(query, page, per_page, DependabotPrLog.processed_at.desc())

    logger.info(
        "list_depsops: total=%d, page=%d, repo=%r, action=%r", total, page, repo, action,
    )

    return DependabotPrLogListResponse(
        total=total,
        page=page,
        per_page=per_page,
        data=[DependabotPrLogOut.model_validate(item) for item in items],
    )


@router.get(
    "/stats",
    response_model=DepsOpsStatsResponse,
    summary="DEPSOPSの未解決PRをリポジトリ別に集計",
    description="最新の判定が action=flagged（要確認）のまま残っているPRを"
    "リポジトリ別に件数集計して返す（ダッシュボードの棒グラフ表示用）。",
)
def get_depsops_stats(db: Annotated[Session, Depends(get_db)]) -> DepsOpsStatsResponse:
    """リポジトリ別の未解決（最新状態がflagged）PR件数を集計する。

    DEPSOPS は同じPRについて実行のたびに1行追加する append-only ログのため、
    「未解決」の判定には (repo_full_name, pr_number) ごとの最新1件のみを見る
    必要がある。全件をクライアントに転送して集計すると、履行が増えるにつれて
    ページング回数（往復レイテンシ）が増え続けて表示が遅くなる問題があったため
    （ダッシュボード側の `computeUnresolvedRepoStats` 相当をSQL側に移した）、
    `ROW_NUMBER() OVER (PARTITION BY repo_full_name, pr_number ORDER BY
    processed_at DESC)` で最新行のみに絞り込んでから集計する。
    """
    latest_rank = (
        func.row_number()
        .over(
            partition_by=(DependabotPrLog.repo_full_name, DependabotPrLog.pr_number),
            order_by=DependabotPrLog.processed_at.desc(),
        )
        .label("latest_rank")
    )
    subq = db.query(
        DependabotPrLog.repo_full_name.label("repo_full_name"),
        DependabotPrLog.action.label("action"),
        latest_rank,
    ).subquery()

    rows = (
        db.query(subq.c.repo_full_name, func.count().label("cnt"))
        .filter(subq.c.latest_rank == 1, subq.c.action == "flagged")
        .group_by(subq.c.repo_full_name)
        .order_by(func.count().desc())
        .all()
    )
    repos = [RepoStat(repo_full_name=r[0], count=r[1]) for r in rows]

    logger.info("get_depsops_stats: %d repos with unresolved PRs", len(repos))
    return DepsOpsStatsResponse(repos=repos)
