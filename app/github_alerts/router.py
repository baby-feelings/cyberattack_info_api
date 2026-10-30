"""GitHub のセキュリティアラートの API ルーター（Issue #402）。

GET /api/github-alerts          – アラートの一覧（種類・リポジトリ・解決状態で絞り込み）
                                  ＋取得不可の項目
GET /api/github-alerts/compare  – Dependabot alerts と DEPSCAN の検知の突き合わせ（片方だけの差分）
POST /admin/github-alerts-crawl – 手動実行（バックグラウンド）

他の検知 API と同じく、`X-API-KEY` または GitHub ログインのセッションを要求し、セッション認証時は
本人所有のリポジトリのみを返す。
"""
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query, Security
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.auth.api_key import require_api_key, require_api_key_or_session
from app.core.background import run_in_background
from app.core.database import get_db
from app.github_alerts.crawler import fetch_and_store_github_alerts
from app.github_alerts.models import SOURCE_UNAVAILABLE, GithubAlert, GithubAlertSource
from app.github_alerts.repository import dependabot_vs_depscan

router = APIRouter(prefix="/api/github-alerts", tags=["github-alerts"])
admin_router = APIRouter(tags=["admin"])


class GithubAlertOut(BaseModel):
    """GitHub のアラート1件（シークレットの値は、含まれない）。"""

    model_config = ConfigDict(from_attributes=True)

    kind: str
    repo_full_name: str
    number: int
    severity: str | None
    title: str
    html_url: str
    detail: dict[str, Any]
    detected_at: str
    resolved_at: str | None


class UnavailableSource(BaseModel):
    """取得できなかった項目（機能が無効・権限不足）。"""

    kind: str
    repo_full_name: str
    reason: str | None


class GithubAlertListResponse(BaseModel):
    total: int
    data: list[GithubAlertOut]
    unavailable: list[UnavailableSource]


@admin_router.post(
    "/admin/github-alerts-crawl", dependencies=[Security(require_api_key)], status_code=202,
    summary="GitHub のセキュリティアラートの取り込みを手動実行（バックグラウンド）",
)
def trigger_github_alerts_crawl(
    force: bool = Query(False, description="今日すでに成功実行済みでも強制的に再実行する"),
) -> dict:
    run_in_background("GHALERT", lambda: fetch_and_store_github_alerts(force=force))
    return {"message": "GitHub alerts crawl started in background"}


def _owned(forced_owner: str | None, column: Any) -> Any:
    """セッション認証時の、本人所有のリポジトリの条件（API キーは、絞り込まない）。"""
    return column.like(f"{forced_owner}/%") if forced_owner else True


@router.get(
    "", response_model=GithubAlertListResponse, summary="GitHub のセキュリティアラートの一覧",
    description="secret scanning（履歴に残ったシークレット・有効性）・Dependabot alerts・"
    "code scanning。"
    "既定は未解決のみ。機能が無効・権限不足で取得できないリポジトリは `unavailable` に示す。",
)
def list_github_alerts(
    db: Annotated[Session, Depends(get_db)],
    forced_owner: Annotated[str | None, Depends(require_api_key_or_session)],
    kind: Annotated[Literal["secret", "dependabot", "code"] | None, Query()] = None,
    repo: Annotated[str | None, Query(description="リポジトリ（owner/name）")] = None,
    resolved: Annotated[bool, Query(description="解決済みも含める")] = False,
) -> GithubAlertListResponse:
    query = db.query(GithubAlert).filter(_owned(forced_owner, GithubAlert.repo_full_name))
    sources = db.query(GithubAlertSource).filter(
        _owned(forced_owner, GithubAlertSource.repo_full_name),
        GithubAlertSource.status == SOURCE_UNAVAILABLE,
    )
    if kind:
        query, sources = query.filter(GithubAlert.kind == kind), sources.filter(
            GithubAlertSource.kind == kind)
    if repo:
        query, sources = query.filter(GithubAlert.repo_full_name == repo), sources.filter(
            GithubAlertSource.repo_full_name == repo)
    if not resolved:
        query = query.filter(GithubAlert.resolved_at.is_(None))
    rows = query.order_by(GithubAlert.detected_at.desc(), GithubAlert.id.desc()).all()
    return GithubAlertListResponse(
        total=len(rows),
        data=[
            GithubAlertOut(
                kind=r.kind, repo_full_name=r.repo_full_name, number=r.number,
                severity=r.severity, title=r.title, html_url=r.html_url, detail=r.detail,
                detected_at=r.detected_at.isoformat(),
                resolved_at=r.resolved_at.isoformat() if r.resolved_at else None,
            ) for r in rows
        ],
        unavailable=[
            UnavailableSource(kind=s.kind, repo_full_name=s.repo_full_name, reason=s.reason)
            for s in sources.order_by(GithubAlertSource.repo_full_name, GithubAlertSource.kind)
        ],
    )


@router.get(
    "/compare", summary="Dependabot alerts と DEPSCAN の検知の突き合わせ",
    description="(リポジトリ・エコシステム・パッケージ・勧告ID) で突き合わせ、"
    "両方が検知したもの（重複は"
    "1件）・GitHub だけが検知したもの・DEPSCAN だけが検知したものを返す。片方だけは、検知の抜けか、"
    "データ源の違いの手がかり。",
)
def compare_alerts(
    db: Annotated[Session, Depends(get_db)],
    forced_owner: Annotated[str | None, Depends(require_api_key_or_session)],
    owner: Annotated[str | None, Query(description="リポジトリオーナー")] = None,
) -> dict[str, list[dict[str, Any]]]:
    return dependabot_vs_depscan(db, forced_owner or owner)
