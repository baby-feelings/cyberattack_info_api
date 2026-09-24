"""自アプリのコード脆弱性診断（CODESCAN）API ルーター。

GET /api/codescan        – 検知結果一覧（リポジトリ・重要度・解決状態・CVSS下限でフィルタ）
GET /api/codescan/stats  – リポジトリ別・重要度別の統計情報（未解決分のみ集計）

自アプリの内部コード脆弱性は特定ユーザーに紐づく情報ではないため、DEPSCAN の
GitHub ログインによるオーナー制限は不要で、KEV/OSV/JVN と同じ
`require_public_api_key`（読み取り専用）を使う。
"""
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Security
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.codescan.crawler import fetch_and_scan_code
from app.codescan.models import CodeFinding
from app.codescan.schemas import (
    CodeFindingListResponse,
    CodeFindingOut,
    CodeFindingStatsResponse,
    CodescanCrawlResponse,
    RepoStat,
)
from app.core.auth import require_api_key, require_public_api_key
from app.core.background import run_in_background
from app.core.database import get_db
from app.core.pagination import paginate
from app.core.schemas import SeverityStat

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/codescan", tags=["codescan"])

# 管理者用エンドポイント（/admin/codescan-crawl）。prefix なし・require_api_key で保護する。
admin_router = APIRouter(tags=["admin"])


@admin_router.post(
    "/admin/codescan-crawl",
    dependencies=[Security(require_api_key)],
    summary="自アプリコード脆弱性スキャン手動実行（バックグラウンド）",
    description="GitHub 上の対象リポジトリのソースコードを Semgrep で静的解析する処理を"
    "バックグラウンドで開始する（X-API-KEY 必須）。結果は /api/crawler-logs で確認。",
    status_code=202,
)
def trigger_codescan_crawl() -> CodescanCrawlResponse:
    """自アプリコード脆弱性スキャナーをバックグラウンドで実行する。"""
    logger.info("Manual CODESCAN triggered via /admin/codescan-crawl")
    run_in_background("CODESCAN", fetch_and_scan_code)
    return CodescanCrawlResponse(message="Code vulnerability scan started in background")


@router.get(
    "",
    response_model=CodeFindingListResponse,
    dependencies=[Security(require_public_api_key)],
    summary="自アプリコード脆弱性の検知結果一覧取得",
    description="リポジトリ・重要度・解決状態・CVSS下限値でフィルタリング可能。",
)
def list_codescan(
    db: Annotated[Session, Depends(get_db)],
    page: int = Query(1, ge=1, description="ページ番号（1始まり）"),
    per_page: int = Query(50, ge=1, le=200, description="1ページあたりの件数"),
    repo: str | None = Query(None, description="リポジトリ名絞り込み（例: owner/repo）"),
    owner: str | None = Query(None, description="リポジトリオーナー絞り込み（例: baby-feelings）"),
    severity: str | None = Query(None, description="重要度絞り込み（ERROR/WARNING/INFO）"),
    resolved: bool | None = Query(None, description="解決状態で絞り込み（未指定なら全件）"),
    min_cvss: float | None = Query(None, ge=0, le=10, description="CVSS基本値の下限値で絞り込み"),
) -> CodeFindingListResponse:
    """自アプリのコード脆弱性検知結果を取得する。"""
    query = db.query(CodeFinding)

    if repo:
        query = query.filter(CodeFinding.repo_full_name == repo)
    if owner:
        query = query.filter(CodeFinding.repo_full_name.like(f"{owner}/%"))
    if severity:
        query = query.filter(CodeFinding.severity == severity.upper())
    if resolved is not None:
        if resolved:
            query = query.filter(CodeFinding.resolved_at.is_not(None))
        else:
            query = query.filter(CodeFinding.resolved_at.is_(None))
    if min_cvss is not None:
        query = query.filter(CodeFinding.cvss_score >= min_cvss)

    total, items = paginate(query, page, per_page, CodeFinding.detected_at.desc())

    logger.info(
        "list_codescan: total=%d, page=%d, repo=%r, owner=%r, severity=%r, "
        "resolved=%r, min_cvss=%r",
        total, page, repo, owner, severity, resolved, min_cvss,
    )

    data = [CodeFindingOut.model_validate(item) for item in items]
    return CodeFindingListResponse(total=total, page=page, per_page=per_page, data=data)


@router.get(
    "/stats",
    response_model=CodeFindingStatsResponse,
    dependencies=[Security(require_public_api_key)],
    summary="自アプリコード脆弱性の統計情報",
    description="未解決の検知結果について、リポジトリ別件数・重要度別件数を返す。",
)
def get_codescan_stats(db: Annotated[Session, Depends(get_db)]) -> CodeFindingStatsResponse:
    """未解決の自アプリコード脆弱性を集計して返す。"""
    base = db.query(CodeFinding).filter(CodeFinding.resolved_at.is_(None))
    total = base.count()

    repo_rows = (
        base.with_entities(
            CodeFinding.repo_full_name,
            func.count(CodeFinding.id).label("cnt"),
        )
        .group_by(CodeFinding.repo_full_name)
        .order_by(func.count(CodeFinding.id).desc())
        .all()
    )
    repos = [RepoStat(repo_full_name=r[0], count=r[1]) for r in repo_rows]

    sev_rows = (
        base.with_entities(
            CodeFinding.severity,
            func.count(CodeFinding.id).label("cnt"),
        )
        .group_by(CodeFinding.severity)
        .order_by(func.count(CodeFinding.id).desc())
        .all()
    )
    severities = [SeverityStat(severity=r[0] or "N/A", count=r[1]) for r in sev_rows]

    logger.info("get_codescan_stats: total=%d, repos=%d", total, len(repos))
    return CodeFindingStatsResponse(total=total, repos=repos, severities=severities)
