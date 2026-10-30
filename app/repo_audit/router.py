"""リポジトリの設定の監査の API ルーター（Issue #398）。

GET /api/repo-audit           – リポジトリごとのスコア・各項目の判定・前回からの変化と、
                                改善すべき件数
POST /admin/repo-audit-crawl  – 手動実行（バックグラウンド）

他の API と同じく、`X-API-KEY` または GitHub ログインのセッションを要求し、セッション認証時は
本人所有のリポジトリのみを返す（他のユーザーのリポジトリの設定を見せないため）。
"""
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Security
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth.api_key import require_api_key, require_api_key_or_session
from app.core.background import run_in_background
from app.core.database import get_db
from app.repo_audit.checks import NG
from app.repo_audit.crawler import fetch_and_audit_repos
from app.repo_audit.models import RepoAudit

router = APIRouter(prefix="/api/repo-audit", tags=["repo-audit"])
admin_router = APIRouter(tags=["admin"])


class RepoAuditOut(BaseModel):
    repo_full_name: str
    score: int | None
    issues: int
    checks: list[dict[str, Any]]
    changes: list[dict[str, Any]]
    audited_at: str


class RepoAuditResponse(BaseModel):
    total: int
    repos_with_issues: int
    data: list[RepoAuditOut]


@admin_router.post(
    "/admin/repo-audit-crawl", dependencies=[Security(require_api_key)], status_code=202,
    summary="リポジトリの設定の監査を手動実行（バックグラウンド）",
)
def trigger_repo_audit(
    force: bool = Query(False, description="今日すでに成功実行済みでも強制的に再実行する"),
) -> dict:
    run_in_background("REPOAUDIT", lambda: fetch_and_audit_repos(force=force))
    return {"message": "Repo audit started in background"}


@router.get(
    "", response_model=RepoAuditResponse, summary="リポジトリの設定の監査結果（スコア）",
    description="secret scanning・push protection・Dependabot・ブランチ保護・フォーク・"
    "デプロイキー・"
    "Webhook の点検結果と、0〜100 のスコア。取得できない項目は status=unavailable（取得不可）、"
    "非公開の無料リポジトリのブランチ保護は status=not_enforceable（強制できない）で、"
    "不備と区別する。"
    "既定はスコアの低い順。",
)
def get_repo_audit(
    db: Annotated[Session, Depends(get_db)],
    forced_owner: Annotated[str | None, Depends(require_api_key_or_session)],
    only_issues: Annotated[bool, Query(description="改善すべき項目があるリポジトリだけ")] = False,
) -> RepoAuditResponse:
    query = db.query(RepoAudit)
    if forced_owner:
        query = query.filter(RepoAudit.repo_full_name.like(f"{forced_owner}/%"))
    rows = [
        RepoAuditOut(
            repo_full_name=r.repo_full_name, score=r.score,
            issues=sum(1 for c in r.checks if c["status"] == NG),
            checks=r.checks, changes=r.changes, audited_at=r.audited_at.isoformat(),
        ) for r in query.all()
    ]
    # スコアの低い順（点検できなかったものは、最後）
    rows.sort(key=lambda r: (r.score is None, r.score or 0, r.repo_full_name))
    with_issues = [r for r in rows if r.issues]
    return RepoAuditResponse(
        total=len(rows), repos_with_issues=len(with_issues),
        data=with_issues if only_issues else rows,
    )
