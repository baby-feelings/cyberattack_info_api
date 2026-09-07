"""OSV 脆弱性 API ルーター。

GET /api/osv        – 直近 N 日の OSV 脆弱性一覧（ページネーション・フィルタ対応）
GET /api/osv/stats  – エコシステム別・重要度別・月別の統計情報
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Security
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.core.auth import require_api_key, require_public_api_key
from app.core.background import run_in_background
from app.core.database import get_db
from app.core.db_utils import year_month_expr
from app.core.schemas import MonthlyStat
from app.osv.crawler import fetch_and_store_osv
from app.osv.models import OsvVulnerability
from app.osv.schemas import (
    OsvEcosystemStat,
    OsvListResponse,
    OsvSeverityStat,
    OsvStatsResponse,
    OsvVulnerabilityOut,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/osv",
    tags=["osv"],
    dependencies=[Depends(require_public_api_key)],
)

# 管理者用エンドポイント（/admin/osv-crawl）。prefix なし・require_api_key で保護する。
admin_router = APIRouter(tags=["admin"])


@admin_router.post(
    "/admin/osv-crawl",
    dependencies=[Security(require_api_key)],
    summary="OSV クローラー手動実行（バックグラウンド）",
    description="OSV API からの脆弱性取得をバックグラウンドで開始する（X-API-KEY 必須）。"
    "結果は /api/crawler-logs で確認。",
    status_code=202,
)
def trigger_osv_crawl(
    days: int | None = Query(
        None, ge=1, le=365, description="取得対象の直近日数（省略時は OSV_DAYS）"
    ),
) -> dict:
    """OSV クローラーをバックグラウンドで実行する。"""
    logger.info("Manual OSV crawl triggered via /admin/osv-crawl (days=%s)", days)
    run_in_background("OSV", lambda: fetch_and_store_osv(days=days))
    return {"message": f"OSV crawl started in background (days={days or 'default'})"}


@router.get(
    "",
    response_model=OsvListResponse,
    summary="OSV 脆弱性一覧取得",
    description=(
        "直近 N 日以内に更新された OSV 脆弱性を返す。"
        "エコシステム・重要度・キーワードでフィルタリング可能。"
    ),
)
def list_osv(
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1, description="ページ番号（1始まり）"),
    per_page: int = Query(50, ge=1, le=200, description="1ページあたりの件数"),
    days: int = Query(30, ge=1, le=365, description="直近何日分を取得するか"),
    ecosystem: str | None = Query(None, description="エコシステム絞り込み（例: PyPI / npm）"),
    severity: str | None = Query(
        None, description="重要度絞り込み（CRITICAL / HIGH / MEDIUM / LOW）"
    ),
    search: str | None = Query(
        None, description="OSV ID・パッケージ名・概要のキーワード検索"
    ),
    sort_by: Literal["modified", "cvss"] = Query(
        "modified", description="ソートキー（modified: 更新日時降順 / cvss: CVSSスコア降順）"
    ),
    updated_since: datetime | None = Query(
        None, description="この日時以降に内容が更新されたレコードのみ返す（差分取得用、ISO 8601）",
    ),
) -> OsvListResponse:
    """直近 N 日以内に更新された OSV 脆弱性を取得する。"""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    query = db.query(OsvVulnerability).filter(OsvVulnerability.modified >= cutoff)

    # 差分取得（増分同期）: 新規追加または内容変更があったレコードのみに絞り込む
    if updated_since is not None:
        query = query.filter(OsvVulnerability.updated_at >= updated_since)

    # エコシステムフィルタ（完全一致）
    if ecosystem:
        query = query.filter(OsvVulnerability.ecosystem == ecosystem)

    # 重要度フィルタ（大文字統一）
    if severity:
        query = query.filter(OsvVulnerability.severity == severity.upper())

    # キーワード検索（OSV ID / パッケージ名 / 概要の部分一致）
    if search:
        kw = f"%{search}%"
        query = query.filter(
            or_(
                OsvVulnerability.osv_id.ilike(kw),
                OsvVulnerability.package_name.ilike(kw),
                OsvVulnerability.summary.ilike(kw),
            )
        )

    total = query.count()
    offset = (page - 1) * per_page

    # ソート順の適用（cvss 指定時は CVSS スコア降順、NULL は末尾）
    if sort_by == "cvss":
        order = OsvVulnerability.cvss_score.desc().nulls_last()  # type: ignore[union-attr,assignment]
    else:
        order = OsvVulnerability.modified.desc()  # type: ignore[assignment]

    items = (
        query.order_by(order)
        .offset(offset)
        .limit(per_page)
        .all()
    )

    logger.info(
        "list_osv: total=%d, page=%d, ecosystem=%r, severity=%r, search=%r, sort_by=%r",
        total, page, ecosystem, severity, search, sort_by,
    )

    return OsvListResponse(
        total=total,
        page=page,
        per_page=per_page,
        data=[OsvVulnerabilityOut.model_validate(item) for item in items],
    )


@router.get(
    "/stats",
    response_model=OsvStatsResponse,
    summary="OSV 統計情報",
    description="エコシステム別件数・重要度分布・月別トレンドを返す。",
)
def get_osv_stats(
    db: Annotated[Session, Depends(get_db)],
    days: int = Query(30, ge=1, le=365, description="集計対象の日数"),
) -> OsvStatsResponse:
    """エコシステム・重要度・月別の統計を集計して返す。"""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    base = db.query(OsvVulnerability).filter(OsvVulnerability.modified >= cutoff)

    total = base.count()

    # エコシステム別件数（降順）
    eco_rows = (
        base.with_entities(
            OsvVulnerability.ecosystem,
            func.count(OsvVulnerability.id).label("cnt"),
        )
        .group_by(OsvVulnerability.ecosystem)
        .order_by(func.count(OsvVulnerability.id).desc())
        .all()
    )
    ecosystems = [OsvEcosystemStat(ecosystem=r[0], count=r[1]) for r in eco_rows]

    # 重要度別件数（降順）
    sev_rows = (
        base.with_entities(
            OsvVulnerability.severity,
            func.count(OsvVulnerability.id).label("cnt"),
        )
        .group_by(OsvVulnerability.severity)
        .order_by(func.count(OsvVulnerability.id).desc())
        .all()
    )
    severities = [
        OsvSeverityStat(severity=r[0] or "N/A", count=r[1]) for r in sev_rows
    ]

    # 月別トレンド（SQLite/PostgreSQL 両対応）
    ym_expr = year_month_expr(OsvVulnerability.modified)
    monthly_rows = (
        base.with_entities(ym_expr.label("ym"), func.count(OsvVulnerability.id).label("cnt"))
        .group_by(ym_expr)
        .order_by(ym_expr)
        .all()
    )
    monthly_trend = [MonthlyStat(year_month=r[0], count=r[1]) for r in monthly_rows]

    logger.info("get_osv_stats: total=%d, ecosystems=%d", total, len(ecosystems))
    return OsvStatsResponse(
        total=total,
        ecosystems=ecosystems,
        severities=severities,
        monthly_trend=monthly_trend,
    )
