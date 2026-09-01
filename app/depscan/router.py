"""依存ライブラリ脆弱性スキャン（DEPSCAN）API ルーター。

GET /api/depscan        – 検知結果一覧（リポジトリ・エコシステム・重要度・解決状態でフィルタ）
GET /api/depscan/stats  – リポジトリ別・重要度別の統計情報（未解決分のみ集計）
"""
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.auth import require_api_key
from app.core.database import get_db
from app.core.schemas import SeverityStat
from app.depscan.models import DependencyFinding
from app.depscan.schemas import (
    DependencyFindingListResponse,
    DependencyFindingOut,
    DependencyFindingStatsResponse,
    RepoStat,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/depscan",
    tags=["depscan"],
    dependencies=[Depends(require_api_key)],
)


@router.get(
    "",
    response_model=DependencyFindingListResponse,
    summary="依存ライブラリ脆弱性の検知結果一覧取得",
    description="リポジトリ・エコシステム・重要度・解決状態でフィルタリング可能。",
)
def list_depscan(
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1, description="ページ番号（1始まり）"),
    per_page: int = Query(50, ge=1, le=200, description="1ページあたりの件数"),
    repo: str | None = Query(None, description="リポジトリ名絞り込み（例: owner/repo）"),
    ecosystem: str | None = Query(None, description="エコシステム絞り込み（例: PyPI / npm）"),
    severity: str | None = Query(
        None, description="重要度絞り込み（CRITICAL / HIGH / MEDIUM / LOW）"
    ),
    resolved: bool | None = Query(None, description="解決状態で絞り込み（未指定なら全件）"),
) -> DependencyFindingListResponse:
    """依存ライブラリ脆弱性の検知結果を取得する。"""
    query = db.query(DependencyFinding)

    if repo:
        query = query.filter(DependencyFinding.repo_full_name == repo)
    if ecosystem:
        query = query.filter(DependencyFinding.ecosystem == ecosystem)
    if severity:
        query = query.filter(DependencyFinding.severity == severity.upper())
    if resolved is not None:
        if resolved:
            query = query.filter(DependencyFinding.resolved_at.is_not(None))
        else:
            query = query.filter(DependencyFinding.resolved_at.is_(None))

    total = query.count()
    offset = (page - 1) * per_page

    items = (
        query.order_by(DependencyFinding.detected_at.desc())
        .offset(offset)
        .limit(per_page)
        .all()
    )

    logger.info(
        "list_depscan: total=%d, page=%d, repo=%r, ecosystem=%r, severity=%r, resolved=%r",
        total, page, repo, ecosystem, severity, resolved,
    )

    return DependencyFindingListResponse(
        total=total,
        page=page,
        per_page=per_page,
        data=[DependencyFindingOut.model_validate(item) for item in items],
    )


@router.get(
    "/stats",
    response_model=DependencyFindingStatsResponse,
    summary="依存ライブラリ脆弱性の統計情報",
    description="未解決の検知結果について、リポジトリ別件数・重要度別件数を返す。",
)
def get_depscan_stats(
    db: Annotated[Session, Depends(get_db)],
) -> DependencyFindingStatsResponse:
    """未解決の依存ライブラリ脆弱性を集計して返す。"""
    base = db.query(DependencyFinding).filter(DependencyFinding.resolved_at.is_(None))

    total = base.count()

    repo_rows = (
        base.with_entities(
            DependencyFinding.repo_full_name,
            func.count(DependencyFinding.id).label("cnt"),
        )
        .group_by(DependencyFinding.repo_full_name)
        .order_by(func.count(DependencyFinding.id).desc())
        .all()
    )
    repos = [RepoStat(repo_full_name=r[0], count=r[1]) for r in repo_rows]

    sev_rows = (
        base.with_entities(
            DependencyFinding.severity,
            func.count(DependencyFinding.id).label("cnt"),
        )
        .group_by(DependencyFinding.severity)
        .order_by(func.count(DependencyFinding.id).desc())
        .all()
    )
    severities = [SeverityStat(severity=r[0] or "N/A", count=r[1]) for r in sev_rows]

    logger.info("get_depscan_stats: total=%d, repos=%d", total, len(repos))
    return DependencyFindingStatsResponse(total=total, repos=repos, severities=severities)
