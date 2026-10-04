"""OSV 脆弱性 API ルーター。

GET /api/osv          – 直近 N 日の OSV 脆弱性一覧（ページネーション・フィルタ対応）
GET /api/osv/stats    – エコシステム別・重要度別・月別の統計情報
GET /api/osv/{osv_id} – OSV ID 個別取得（Issue #134：`format=stix` でSTIX 2.1形式も返せる）
"""
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, Security
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.auth import require_api_key, require_public_api_key
from app.core.background import run_in_background
from app.core.database import get_db
from app.core.db_utils import year_month_expr
from app.core.pagination import paginate
from app.core.schemas import MonthlyStat
from app.osv.crawler import fetch_and_store_osv
from app.osv.filters import OsvListFilter
from app.osv.models import OsvVulnerability
from app.osv.schemas import (
    OsvEcosystemStat,
    OsvListResponse,
    OsvSeverityStat,
    OsvStatsResponse,
    OsvVulnerabilityOut,
)
from app.osv.stix import build_stix_bundle

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
    force: bool = Query(
        False, description="今日すでに成功実行済みでも強制的に再実行する（Issue #239）",
    ),
) -> dict:
    """OSV クローラーをバックグラウンドで実行する。"""
    logger.info("Manual OSV crawl triggered via /admin/osv-crawl (days=%s, force=%s)", days, force)
    run_in_background("OSV", lambda: fetch_and_store_osv(days=days, force=force))
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
    flt: OsvListFilter = Depends(),
) -> OsvListResponse:
    """直近 N 日以内に更新された OSV 脆弱性を取得する。"""
    query = flt.apply(flt.base_query(db))
    order = flt.order()

    total, items = paginate(query, page, per_page, order)

    logger.info(
        "list_osv: total=%d, page=%d, ecosystem=%r, severity=%r, search=%r, sort_by=%r",
        total, page, flt.ecosystem, flt.severity, flt.search, flt.sort_by,
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


@router.get(
    "/{osv_id}",
    response_model=None,
    summary="OSV ID 個別取得",
    description="OSV ID を指定して該当する全レコードを取得する。"
    "OSV は (osv_id, ecosystem, package_name) の複合キーが自然キーのため、"
    "1つの OSV ID が複数パッケージに影響する場合は複数件のリストを返す。"
    "`format=stix` を指定すると STIX 2.1 の Bundle 形式で返す（Issue #134）。",
)
def get_osv_vulnerability(
    osv_id: str,
    db: Annotated[Session, Depends(get_db)],
    format: Literal["json", "stix"] = Query("json", description="出力形式"),
) -> list[OsvVulnerabilityOut] | Response:
    """指定した OSV ID に該当する全レコードを返す。1件も無ければ 404 を返す。

    `format`引数の型が`response_model=list[OsvVulnerabilityOut]`と両立しないため、
    本エンドポイントは response_model を指定しない（app.kev.router.get_vulnerability
    と同じ理由。詳細はそちらのdocstring参照）。
    """
    items = db.query(OsvVulnerability).filter(OsvVulnerability.osv_id == osv_id).all()
    if not items:
        raise HTTPException(status_code=404, detail=f"{osv_id} は見つかりませんでした。")

    logger.info("get_osv_vulnerability: osv_id=%s, format=%s, count=%d", osv_id, format, len(items))

    if format == "stix":
        bundle = build_stix_bundle(items)
        return Response(
            content=json.dumps(bundle),
            media_type="application/stix+json;version=2.1",
        )
    return [OsvVulnerabilityOut.model_validate(item) for item in items]
