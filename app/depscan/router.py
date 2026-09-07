"""依存ライブラリ脆弱性スキャン（DEPSCAN）API ルーター。

GET /api/depscan        – 検知結果一覧（リポジトリ・エコシステム・重要度・解決状態でフィルタ）
GET /api/depscan/stats  – リポジトリ別・重要度別の統計情報（未解決分のみ集計）

認証は `X-API-KEY`（フルアクセス）または `Authorization: Bearer <セッショントークン>`
（GitHub ログイン経由。本人所有リポジトリのみに強制的に絞り込む）のいずれかを受け付ける。
"""
import hmac
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.security import APIKeyHeader
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.auth.session import decode_session_token
from app.core.config import settings
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

router = APIRouter(prefix="/api/depscan", tags=["depscan"])

_api_key_header = APIKeyHeader(name="X-API-KEY", auto_error=False)
_bearer_header = APIKeyHeader(name="Authorization", auto_error=False)


def _resolve_access(
    api_key: str | None = Depends(_api_key_header),
    authorization: str | None = Depends(_bearer_header),
) -> str | None:
    """`X-API-KEY` または `Authorization: Bearer <session token>` を検証する。

    Returns:
        セッショントークン認証の場合はログイン中の GitHub ユーザー名
        （呼び出し側でこの値に強制的に絞り込む）。API キー認証の場合は
        None（絞り込みなし＝フルアクセス。Claude Code 等の既存クライアント向け）。
    """
    if api_key and hmac.compare_digest(api_key, settings.API_KEY):
        return None
    if authorization and authorization.lower().startswith("bearer "):
        username = decode_session_token(authorization[len("bearer "):].strip())
        if username is not None:
            return username
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid or missing credentials. Provide X-API-KEY or "
        "Authorization: Bearer <session token>.",
    )


@router.get(
    "",
    response_model=DependencyFindingListResponse,
    summary="依存ライブラリ脆弱性の検知結果一覧取得",
    description="リポジトリ・エコシステム・重要度・解決状態でフィルタリング可能。",
)
def list_depscan(
    db: Annotated[Session, Depends(get_db)],
    forced_owner: Annotated[str | None, Depends(_resolve_access)],
    page: int = Query(1, ge=1, description="ページ番号（1始まり）"),
    per_page: int = Query(50, ge=1, le=200, description="1ページあたりの件数"),
    repo: str | None = Query(None, description="リポジトリ名絞り込み（例: owner/repo）"),
    owner: str | None = Query(None, description="リポジトリオーナー絞り込み（例: baby-feelings）"),
    ecosystem: str | None = Query(None, description="エコシステム絞り込み（例: PyPI / npm）"),
    severity: str | None = Query(
        None, description="重要度絞り込み（CRITICAL / HIGH / MEDIUM / LOW）"
    ),
    resolved: bool | None = Query(None, description="解決状態で絞り込み（未指定なら全件）"),
) -> DependencyFindingListResponse:
    """依存ライブラリ脆弱性の検知結果を取得する。

    セッショントークン認証時は `owner` クエリパラメータの指定に関わらず、
    ログイン中の GitHub ユーザー本人が所有するリポジトリのみに強制的に絞り込む。
    """
    if forced_owner is not None:
        owner = forced_owner
        # `repo` は owner とは独立した完全一致フィルタのため、セッション認証時に
        # 他人のリポジトリを直接指定して owner 制限を迂回できないようガードする
        if repo is not None and not repo.startswith(f"{forced_owner}/"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only query repositories you own.",
            )

    query = db.query(DependencyFinding)

    if repo:
        query = query.filter(DependencyFinding.repo_full_name == repo)
    if owner:
        query = query.filter(DependencyFinding.repo_full_name.like(f"{owner}/%"))
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
        "list_depscan: total=%d, page=%d, repo=%r, owner=%r, ecosystem=%r, "
        "severity=%r, resolved=%r",
        total, page, repo, owner, ecosystem, severity, resolved,
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
    forced_owner: Annotated[str | None, Depends(_resolve_access)],
) -> DependencyFindingStatsResponse:
    """未解決の依存ライブラリ脆弱性を集計して返す。

    セッショントークン認証時は、ログイン中の GitHub ユーザー本人が所有する
    リポジトリのみに強制的に絞り込む。
    """
    base = db.query(DependencyFinding).filter(DependencyFinding.resolved_at.is_(None))
    if forced_owner is not None:
        base = base.filter(DependencyFinding.repo_full_name.like(f"{forced_owner}/%"))

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
