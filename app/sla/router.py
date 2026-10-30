"""脆弱性への対応状況（SLA・MTTR）API ルーター。

GET /api/sla  – 期限超過の検知・重要度別／リポジトリ別の件数・平均対応日数（MTTR）

DEPSCAN と同じく、`X-API-KEY` または GitHub ログインのセッションを要求し、セッション認証時は
本人所有のリポジトリのみに強制的に絞り込む（他のユーザーのリポジトリ名・検知を見せないため）。
"""
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Security
from sqlalchemy.orm import Session

from app.auth.api_key import require_api_key, require_api_key_or_session
from app.core.background import run_in_background
from app.core.config import settings
from app.core.database import get_db
from app.core.operating_status import OperatingQuery
from app.depscan.filters import DepscanListFilter
from app.sla.digest import run_sla_digest
from app.sla.policy import SlaPolicy
from app.sla.report import build_report
from app.sla.schemas import SlaReportOut

router = APIRouter(prefix="/api/sla", tags=["sla"])

# 管理者用エンドポイント（/admin/sla-digest）。prefix なし・require_api_key で保護する。
admin_router = APIRouter(tags=["admin"])


@admin_router.post(
    "/admin/sla-digest",
    dependencies=[Security(require_api_key)],
    summary="脆弱性への対応状況の週次まとめを手動で送る（バックグラウンド）",
    description="管理者（GITHUB_USERNAME）自身のリポジトリの対応状況を集計し、"
    "Slack に送る処理をバックグラウンドで開始する（X-API-KEY 必須）。",
    status_code=202,
)
def trigger_sla_digest() -> dict:
    """週次のまとめを、いま送る（動作確認・再送用）。"""
    run_in_background("SLA_DIGEST", run_sla_digest)
    return {"message": "SLA digest started in background"}


@router.get(
    "",
    response_model=SlaReportOut,
    summary="脆弱性への対応状況（期限超過・平均対応日数）",
    description="DEPSCAN の検知について、重要度ごとの対応期限（CRITICAL 7日・HIGH 30日・"
    "MEDIUM 90日。KEV 掲載済みは 7 日。環境変数 SLA_* で変更可）を超えている検知と、"
    "検知から解決までの平均日数（MTTR）を返す。LOW・重要度不明は期限なし。"
    "セッション認証時は本人所有のリポジトリのみ。",
)
def get_sla_report(
    db: Annotated[Session, Depends(get_db)],
    forced_owner: Annotated[str | None, Depends(require_api_key_or_session)],
    repo: Annotated[
        str | None, Query(description="リポジトリ名絞り込み（例: owner/repo）"),
    ] = None,
    owner: Annotated[
        str | None, Query(description="リポジトリオーナー絞り込み（例: baby-feelings）"),
    ] = None,
    operating: OperatingQuery = "all",
    window_days: Annotated[
        int,
        Query(
            ge=1, le=180,
            description="MTTR を集計する、解決済みの期間（日。既定は SLA_MTTR_WINDOW_DAYS）。"
            "解決済みの保持期間（180日）が上限",
        ),
    ] = settings.SLA_MTTR_WINDOW_DAYS,
) -> SlaReportOut:
    """対応状況のレポートを返す。"""
    flt = DepscanListFilter(
        repo=repo, owner=owner, ecosystem=None, severity=None, resolved=None,
        operating=operating,
    )
    flt.restrict_to_owner(forced_owner)
    return build_report(db, flt, SlaPolicy.from_settings(), window_days=window_days)
