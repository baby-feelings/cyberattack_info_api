"""DEPSOPS（Dependabot PR 自動運用）API ルーター。

GET /api/depsops – 判定履歴一覧（自動マージ・要確認）。リポジトリ・action でフィルタ可能。
POST /admin/dependabot-ops – 手動トリガー（バックグラウンド）。
"""
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Security
from sqlalchemy.orm import Session

from app.core.auth import require_api_key, require_public_api_key
from app.core.background import run_in_background
from app.core.database import get_db
from app.core.pagination import paginate
from app.depsops.models import DependabotPrLog
from app.depsops.runner import run_dependabot_ops
from app.depsops.schemas import DependabotPrLogListResponse, DependabotPrLogOut

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
