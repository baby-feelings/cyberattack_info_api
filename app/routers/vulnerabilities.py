"""脆弱性情報 API ルーター。
GET /api/vulnerabilities         – 一覧取得（ページネーション・フィルタリング）
GET /api/vulnerabilities/recent  – 直近追加データ取得
GET /api/vulnerabilities/stats   – 統計情報取得
GET /api/vulnerabilities/{cve_id} – CVE 個別取得
"""
import logging
from datetime import date, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.auth import require_api_key
from app.database import get_db
from app.db_utils import year_month_expr
from app.models import Vulnerability
from app.schemas import (
    MonthlyStat,
    StatsResponse,
    VendorStat,
    VulnerabilityListResponse,
    VulnerabilityOut,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/vulnerabilities",
    tags=["vulnerabilities"],
    # 全エンドポイントに X-API-KEY 認証を適用
    dependencies=[Depends(require_api_key)],
)


@router.get(
    "",
    response_model=VulnerabilityListResponse,
    summary="脆弱性一覧取得",
    description="蓄積された脆弱性情報を一覧で返す。ページネーション・キーワード検索に対応。",
)
def list_vulnerabilities(
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1, description="ページ番号（1始まり）"),
    per_page: int = Query(50, ge=1, le=500, description="1ページあたりの件数"),
    search: str | None = Query(None, description="ベンダー名・製品名の部分一致検索"),
    vendor: str | None = Query(None, description="ベンダー名での絞り込み（完全一致）"),
    product: str | None = Query(None, description="製品名での絞り込み（部分一致）"),
) -> VulnerabilityListResponse:
    """脆弱性一覧を取得する。

    - `search`: vendor_project または product の部分一致フィルタ
    - `vendor`: vendor_project の完全一致フィルタ
    - `product`: product の部分一致フィルタ
    - 最新の date_added 順でソート
    """
    query = db.query(Vulnerability)

    # キーワード検索: ベンダー名 OR 製品名の部分一致
    if search:
        keyword = f"%{search}%"
        query = query.filter(
            or_(
                Vulnerability.vendor_project.ilike(keyword),
                Vulnerability.product.ilike(keyword),
            )
        )

    # ベンダー名の完全一致フィルタ
    if vendor:
        query = query.filter(Vulnerability.vendor_project == vendor)

    # 製品名の部分一致フィルタ
    if product:
        query = query.filter(Vulnerability.product.ilike(f"%{product}%"))

    # 総件数をカウント（ページネーション用）
    total = query.count()

    # 最新の追加日順でソートし、ページネーションを適用
    offset = (page - 1) * per_page
    items = (
        query.order_by(Vulnerability.date_added.desc())
        .offset(offset)
        .limit(per_page)
        .all()
    )

    logger.info(
        "list_vulnerabilities: total=%d, page=%d, per_page=%d, search=%r",
        total, page, per_page, search,
    )

    return VulnerabilityListResponse(
        total=total,
        page=page,
        per_page=per_page,
        data=[VulnerabilityOut.model_validate(item) for item in items],
    )


@router.get(
    "/recent",
    response_model=list[VulnerabilityOut],
    summary="直近の脅威取得",
    description=(
        "過去 N 日以内に CISA KEV に追加された脆弱性を返す。"
        "Claude Code のコンテキストにそのまま流し込みやすいようデータ配列のみを返す。"
    ),
)
def get_recent_vulnerabilities(
    db: Annotated[Session, Depends(get_db)],
    days: int = Query(30, ge=1, le=365, description="過去何日分のデータを取得するか"),
) -> list[VulnerabilityOut]:
    """直近 N 日以内に追加された脆弱性を取得する。
    シンプルなリスト形式で返すことで、Claude Code のコンテキスト連携を最適化する。
    """
    cutoff = date.today() - timedelta(days=days)

    items = (
        db.query(Vulnerability)
        .filter(Vulnerability.date_added >= cutoff)
        .order_by(Vulnerability.date_added.desc())
        .all()
    )

    logger.info(
        "get_recent_vulnerabilities: days=%d, cutoff=%s, count=%d",
        days, cutoff, len(items),
    )

    return [VulnerabilityOut.model_validate(item) for item in items]


@router.get(
    "/stats",
    response_model=StatsResponse,
    summary="脆弱性統計情報",
    description="総件数・ベンダー別ランキング・月別追加トレンドを返す。",
)
def get_stats(
    db: Annotated[Session, Depends(get_db)],
) -> StatsResponse:
    """ベンダー別・月別の集計統計を返す。"""
    total = db.query(func.count(Vulnerability.id)).scalar() or 0

    # ベンダー別件数（上位 10 件）
    vendor_rows = (
        db.query(Vulnerability.vendor_project, func.count(Vulnerability.id).label("cnt"))
        .group_by(Vulnerability.vendor_project)
        .order_by(func.count(Vulnerability.id).desc())
        .limit(10)
        .all()
    )
    top_vendors = [VendorStat(vendor_project=r[0], count=r[1]) for r in vendor_rows]

    # 月別追加件数（直近 12 ヶ月）
    cutoff = date.today() - timedelta(days=365)
    date_expr = year_month_expr(Vulnerability.date_added)
    monthly_rows = (
        db.query(
            date_expr.label("ym"),
            func.count(Vulnerability.id).label("cnt"),
        )
        .filter(Vulnerability.date_added >= cutoff)
        .group_by(date_expr)
        .order_by(date_expr)
        .all()
    )
    monthly_trend = [MonthlyStat(year_month=r[0], count=r[1]) for r in monthly_rows]

    logger.info("get_stats: total=%d, vendors=%d", total, len(top_vendors))
    return StatsResponse(
        total_vulnerabilities=total,
        top_vendors=top_vendors,
        monthly_trend=monthly_trend,
    )


@router.get(
    "/{cve_id}",
    response_model=VulnerabilityOut,
    summary="CVE 個別取得",
    description="CVE ID を指定して脆弱性の詳細を1件取得する。",
)
def get_vulnerability(
    cve_id: str,
    db: Annotated[Session, Depends(get_db)],
) -> VulnerabilityOut:
    """指定した CVE ID の脆弱性を返す。存在しない場合は 404 を返す。"""
    # CVE ID は大文字小文字を問わず一致させる
    item = (
        db.query(Vulnerability)
        .filter(func.upper(Vulnerability.cve_id) == cve_id.upper())
        .first()
    )
    if item is None:
        raise HTTPException(status_code=404, detail=f"{cve_id} は見つかりませんでした。")

    logger.info("get_vulnerability: cve_id=%s", cve_id)
    return VulnerabilityOut.model_validate(item)
