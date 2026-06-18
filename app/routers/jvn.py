"""JVN 脆弱性 API ルーター。

GET /api/jvn        – 直近 N 日の JVN 脆弱性一覧（ページネーション・フィルタ対応）
GET /api/jvn/stats  – 重要度別・月別の統計情報
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement  # noqa: F401 — used in type annotation

from app.auth import require_api_key
from app.database import engine, get_db
from app.models import JvnVulnerability
from app.schemas import (
    JvnListResponse,
    JvnSeverityStat,
    JvnStatsResponse,
    JvnVulnerabilityOut,
    MonthlyStat,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/jvn",
    tags=["jvn"],
    dependencies=[Depends(require_api_key)],
)


def _year_month_expr(column: Any) -> ColumnElement[str]:
    """SQLite / PostgreSQL 両対応の YYYY-MM フォーマット式を返す。"""
    if "sqlite" in engine.dialect.name:
        return func.strftime("%Y-%m", column)  # type: ignore[return-value]
    # PostgreSQL
    return func.to_char(column, "YYYY-MM")  # type: ignore[return-value]


@router.get(
    "",
    response_model=JvnListResponse,
    summary="JVN 脆弱性一覧取得",
    description=(
        "直近 N 日以内に更新された JVN 脆弱性を返す。"
        "重要度・キーワードでフィルタリング可能。"
    ),
)
def list_jvn(
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1, description="ページ番号（1始まり）"),
    per_page: int = Query(50, ge=1, le=200, description="1ページあたりの件数"),
    days: int = Query(30, ge=1, le=365, description="直近何日分を取得するか"),
    severity: str | None = Query(
        None, description="重要度絞り込み（High / Medium / Low）"
    ),
    search: str | None = Query(
        None, description="JVNDB ID・タイトル・概要のキーワード検索"
    ),
    sort_by: str = Query(
        "modified",
        description="ソートキー（modified: 更新日時降順 / cvss: CVSSスコア降順）",
    ),
) -> JvnListResponse:
    """直近 N 日以内に更新された JVN 脆弱性を取得する。"""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    query = db.query(JvnVulnerability).filter(
        JvnVulnerability.date_last_modified >= cutoff
    )

    # 重要度フィルタ（先頭大文字統一: high → High）
    if severity:
        query = query.filter(
            JvnVulnerability.severity == severity.capitalize()
        )

    # キーワード検索（JVNDB ID / タイトル / 概要の部分一致）
    if search:
        kw = f"%{search}%"
        query = query.filter(
            or_(
                JvnVulnerability.jvndb_id.ilike(kw),
                JvnVulnerability.title.ilike(kw),
                JvnVulnerability.overview.ilike(kw),
            )
        )

    total = query.count()
    offset = (page - 1) * per_page

    # ソート順の適用（cvss 指定時は CVSS スコア降順、NULL は末尾）
    if sort_by == "cvss":
        order = JvnVulnerability.cvss_score.desc().nulls_last()  # type: ignore[union-attr,assignment]
    else:
        order = JvnVulnerability.date_last_modified.desc()  # type: ignore[assignment]

    items = (
        query.order_by(order)
        .offset(offset)
        .limit(per_page)
        .all()
    )

    logger.info(
        "list_jvn: total=%d, page=%d, severity=%r, search=%r, sort_by=%r",
        total, page, severity, search, sort_by,
    )

    return JvnListResponse(
        total=total,
        page=page,
        per_page=per_page,
        data=[JvnVulnerabilityOut.model_validate(item) for item in items],
    )


@router.get(
    "/stats",
    response_model=JvnStatsResponse,
    summary="JVN 統計情報",
    description="重要度分布・月別トレンドを返す。",
)
def get_jvn_stats(
    db: Annotated[Session, Depends(get_db)],
    days: int = Query(30, ge=1, le=365, description="集計対象の日数"),
) -> JvnStatsResponse:
    """重要度別件数・月別トレンドを集計して返す。"""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    base = db.query(JvnVulnerability).filter(
        JvnVulnerability.date_last_modified >= cutoff
    )

    total = base.count()

    # 重要度別件数（降順）
    sev_rows = (
        base.with_entities(
            JvnVulnerability.severity,
            func.count(JvnVulnerability.id).label("cnt"),
        )
        .group_by(JvnVulnerability.severity)
        .order_by(func.count(JvnVulnerability.id).desc())
        .all()
    )
    severities = [
        JvnSeverityStat(severity=r[0] or "N/A", count=r[1]) for r in sev_rows
    ]

    # 月別トレンド（SQLite/PostgreSQL 両対応）
    ym_expr = _year_month_expr(JvnVulnerability.date_last_modified)
    monthly_rows = (
        base.with_entities(
            ym_expr.label("ym"),
            func.count(JvnVulnerability.id).label("cnt"),
        )
        .group_by(ym_expr)
        .order_by(ym_expr)
        .all()
    )
    monthly_trend = [MonthlyStat(year_month=r[0], count=r[1]) for r in monthly_rows]

    logger.info("get_jvn_stats: total=%d", total)
    return JvnStatsResponse(
        total=total,
        severities=severities,
        monthly_trend=monthly_trend,
    )
