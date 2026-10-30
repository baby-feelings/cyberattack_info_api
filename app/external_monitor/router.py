"""公開サイトの外形監視の API ルーター（Issue #401）。

GET /api/site-monitor           – サイトごとの TLS 証明書の残り日数・見つかった問題
POST /admin/site-monitor-crawl  – 手動実行（バックグラウンド）

他の API と同じく、`X-API-KEY` または GitHub ログインのセッションを要求し、セッション認証時は
本人所有のリポジトリに紐づくサイトのみを返す（設定で足したサイトは、管理者のみ）。
"""
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Security
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth.api_key import require_api_key, require_api_key_or_session
from app.core.background import run_in_background
from app.core.database import get_db
from app.external_monitor.crawler import fetch_and_monitor_sites
from app.external_monitor.models import SiteCheck

router = APIRouter(prefix="/api/site-monitor", tags=["site-monitor"])
admin_router = APIRouter(tags=["admin"])

_SEVERITY_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2}


class SiteCheckOut(BaseModel):
    url: str
    source: str
    repo_full_name: str | None
    tls_days_left: int | None
    # 問題の数（ERROR・WARNING）。INFO（ヘッダーの不足など）は、`findings` で確認する
    issues: int
    findings: list[dict[str, Any]]
    checked_at: str


class SiteMonitorResponse(BaseModel):
    total: int
    sites_with_issues: int
    data: list[SiteCheckOut]


@admin_router.post(
    "/admin/site-monitor-crawl", dependencies=[Security(require_api_key)], status_code=202,
    summary="公開サイトの外形監視を手動実行（バックグラウンド）",
)
def trigger_site_monitor(
    force: bool = Query(False, description="今日すでに成功実行済みでも強制的に再実行する"),
) -> dict:
    run_in_background("EXTMON", lambda: fetch_and_monitor_sites(force=force))
    return {"message": "Site monitor started in background"}


@router.get(
    "", response_model=SiteMonitorResponse, summary="公開サイトの外形監視の結果",
    description="TLS 証明書の期限・セキュリティヘッダー・露出ファイル（.env・.git 等）・"
    "宙ぶらりんの DNS・認証なしで読める Firestore を、GET のみで非侵入に点検した結果。"
    "問題の多い（重大な）サイトが先。",
)
def get_site_monitor(
    db: Annotated[Session, Depends(get_db)],
    forced_owner: Annotated[str | None, Depends(require_api_key_or_session)],
    only_issues: Annotated[
        bool, Query(description="問題（ERROR・WARNING）があるサイトだけ"),
    ] = False,
) -> SiteMonitorResponse:
    query = db.query(SiteCheck)
    if forced_owner:
        query = query.filter(SiteCheck.repo_full_name.like(f"{forced_owner}/%"))

    def worst(row: SiteCheck) -> int:
        return min((_SEVERITY_ORDER.get(f["severity"], 3) for f in row.findings), default=3)

    rows = [
        SiteCheckOut(
            url=r.url, source=r.source, repo_full_name=r.repo_full_name,
            tls_days_left=r.tls_days_left,
            issues=sum(1 for f in r.findings if f["severity"] in ("ERROR", "WARNING")),
            findings=r.findings, checked_at=r.checked_at.isoformat(),
        ) for r in sorted(query.all(), key=lambda r: (worst(r), r.url))
    ]
    with_issues = [r for r in rows if r.issues]
    return SiteMonitorResponse(
        total=len(rows), sites_with_issues=len(with_issues),
        data=with_issues if only_issues else rows,
    )
