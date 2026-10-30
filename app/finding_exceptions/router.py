"""検知の例外（受容・誤検知・影響なし）API ルーター（Issue #403）。

GET    /api/exceptions          – 例外の一覧
POST   /api/exceptions          – 例外の登録（同じ検知に有効な例外があれば更新）
DELETE /api/exceptions/{id}     – 例外の解除
GET    /api/exceptions/vex      – VEX（OpenVEX・CycloneDX）での出力

他の検知 API と同じく、`X-API-KEY` または GitHub ログインのセッションを要求し、セッション認証時は
本人所有のリポジトリのみを対象にする（他のユーザーのリポジトリの例外を、見せも変えもしない）。
承認者は、登録した GitHub ユーザー（API キー経由の場合は管理者 `GITHUB_USERNAME`）。
"""
import json
import logging
from datetime import datetime, timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response, Security
from sqlalchemy.orm import Session

from app.auth.api_key import require_api_key, require_api_key_or_session
from app.core.background import run_in_background
from app.core.config import settings
from app.core.database import get_db
from app.core.db_utils import as_utc
from app.core.owner_scope import is_owned_by
from app.crawler_logs.writer import now_utc
from app.depscan.models import DependencyFinding
from app.finding_exceptions.issue_sync import sync_issues_after_change
from app.finding_exceptions.lifecycle import run_exception_lifecycle
from app.finding_exceptions.matching import (
    active_exceptions,
    dependency_key,
    finding_exists,
)
from app.finding_exceptions.models import KIND_DEPENDENCY, FindingException
from app.finding_exceptions.repository import FindingExceptionRepository
from app.finding_exceptions.schemas import (
    FindingExceptionIn,
    FindingExceptionListResponse,
    FindingExceptionOut,
)
from app.finding_exceptions.vex import build_cyclonedx_vex, build_openvex

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/exceptions", tags=["exceptions"])

# 管理者用エンドポイント（/admin/exception-lifecycle）。prefix なし・require_api_key で保護する。
admin_router = APIRouter(tags=["admin"])

_VEX_MEDIA_TYPES = {
    "openvex": "application/vnd.openvex+json",
    "cyclonedx": "application/vnd.cyclonedx+json",
}


@admin_router.post(
    "/admin/exception-lifecycle",
    dependencies=[Security(require_api_key)],
    summary="例外の期限・修正版の公開の確認を手動で実行する（バックグラウンド）",
    description="期限切れ・修正版の公開で例外を解除し、期限の7日前の通知を送る処理を"
    "バックグラウンドで開始する（X-API-KEY 必須）。",
    status_code=202,
)
def trigger_exception_lifecycle() -> dict:
    """例外の定期ジョブを、いま実行する（動作確認・再実行用）。"""
    run_in_background("EXCEPTION_LIFECYCLE", run_exception_lifecycle)
    return {"message": "Exception lifecycle started in background"}


def _owns(repo_full_name: str, forced_owner: str | None) -> bool:
    """本人所有のリポジトリか（API キー認証＝`forced_owner` が None なら、全リポジトリ）。"""
    return forced_owner is None or is_owned_by(repo_full_name, forced_owner)


def _validate_expiry(body: FindingExceptionIn) -> datetime | None:
    """期限を検証する（受容は必須・未来・上限日数以内）。"""
    if body.expires_at is None:
        if body.requires_expiry():
            raise HTTPException(status_code=422, detail="受容には、期限が必要です。")
        return None
    expires_at = as_utc(body.expires_at)
    now = now_utc()
    if expires_at <= now:
        raise HTTPException(status_code=422, detail="期限は、現在より後の日時にしてください。")
    if expires_at > now + timedelta(days=settings.EXCEPTION_MAX_DAYS):
        raise HTTPException(
            status_code=422,
            detail=f"期限は、{settings.EXCEPTION_MAX_DAYS}日以内にしてください。",
        )
    return expires_at


@router.get(
    "", response_model=FindingExceptionListResponse, summary="検知の例外の一覧",
    description="既定は有効な例外のみ。include_ended=true で、終了（解除・期限切れ・"
    "修正版の公開）した例外も返す。セッション認証時は本人所有のリポジトリのみ。",
)
def list_exceptions(
    db: Annotated[Session, Depends(get_db)],
    forced_owner: Annotated[str | None, Depends(require_api_key_or_session)],
    kind: Annotated[Literal["dependency", "code"] | None, Query(description="検知の種別")] = None,
    repo: Annotated[str | None, Query(description="リポジトリ（owner/name）")] = None,
    owner: Annotated[str | None, Query(description="リポジトリオーナー")] = None,
    include_ended: Annotated[bool, Query(description="終了した例外も含める")] = False,
) -> FindingExceptionListResponse:
    rows = FindingExceptionRepository(db).find(
        kind=kind, repo=repo, owner=forced_owner or owner, include_ended=include_ended,
    )
    return FindingExceptionListResponse(
        total=len(rows), data=[FindingExceptionOut.model_validate(r) for r in rows],
    )


@router.post(
    "", response_model=FindingExceptionOut, status_code=201, summary="検知の例外を登録",
    description="受容（期限必須）・誤検知・影響なしを、理由つきで登録する。同じ検知に有効な"
    "例外があれば、内容を更新する。登録後、リポジトリの GitHub Issue を整える（有効な検知が"
    "0件になれば閉じる）。",
)
def create_exception(
    body: FindingExceptionIn,
    background: BackgroundTasks,
    db: Annotated[Session, Depends(get_db)],
    forced_owner: Annotated[str | None, Depends(require_api_key_or_session)],
) -> FindingException:
    if not _owns(body.repo_full_name, forced_owner):
        raise HTTPException(
            status_code=403, detail="You can only manage exceptions of repositories you own.",
        )
    expires_at = _validate_expiry(body)
    if not finding_exists(db, body.kind, body.repo_full_name, body.finding_key):
        raise HTTPException(status_code=404, detail="対象の検知が見つかりません。")

    row = FindingExceptionRepository(db).upsert_active(
        kind=body.kind, repo_full_name=body.repo_full_name, finding_key=body.finding_key,
        status=body.status, reason=body.reason, expires_at=expires_at,
        approver=forced_owner or settings.GITHUB_USERNAME,
    )
    logger.info(
        "exception created: %s %s %s status=%s by=%s",
        body.kind, body.repo_full_name, body.finding_key, body.status, row.approver,
    )
    background.add_task(
        sync_issues_after_change, body.kind, body.repo_full_name, body.finding_key,
        accepted=True,
    )
    return row


@router.delete(
    "/{exception_id}", response_model=FindingExceptionOut, summary="検知の例外を解除",
    description="例外を解除し、検知を再び「対応中」に戻す。リポジトリの GitHub Issue に再び示す。",
)
def revoke_exception(
    exception_id: int,
    background: BackgroundTasks,
    db: Annotated[Session, Depends(get_db)],
    forced_owner: Annotated[str | None, Depends(require_api_key_or_session)],
) -> FindingException:
    repository = FindingExceptionRepository(db)
    row = repository.get(exception_id)
    # 他のユーザーの例外は、存在そのものを知らせない（404）
    if row is None or not _owns(row.repo_full_name, forced_owner):
        raise HTTPException(status_code=404, detail="例外が見つかりません。")
    if row.ended_at is not None:
        raise HTTPException(status_code=409, detail="この例外は、既に終了しています。")
    row = repository.end(row)
    background.add_task(
        sync_issues_after_change, row.kind, row.repo_full_name, row.finding_key, accepted=False,
    )
    return row


@router.get(
    "/vex", summary="検知の例外を VEX 形式でエクスポート",
    description="指定リポジトリの、有効な例外（依存ライブラリ）を、OpenVEX 0.2.0 または"
    "CycloneDX 1.5 の VEX で出力する。受容=affected（対応を記載）・誤検知／影響なし=not_affected。",
)
def export_vex(
    db: Annotated[Session, Depends(get_db)],
    forced_owner: Annotated[str | None, Depends(require_api_key_or_session)],
    repo: Annotated[str, Query(description="対象リポジトリ（owner/name）")],
    format: Annotated[Literal["openvex", "cyclonedx"], Query(description="出力形式")] = "openvex",
) -> Response:
    if not _owns(repo, forced_owner):
        raise HTTPException(
            status_code=403, detail="You can only export repositories you own.",
        )
    exceptions = active_exceptions(db, KIND_DEPENDENCY).filter(
        FindingException.repo_full_name == repo,
    ).all()
    findings = {
        dependency_key(f.ecosystem, f.package_name, f.osv_id): f
        for f in db.query(DependencyFinding).filter(DependencyFinding.repo_full_name == repo)
    }
    rows = [(e, findings[e.finding_key]) for e in exceptions if e.finding_key in findings]
    document = (
        build_openvex(repo, rows) if format == "openvex" else build_cyclonedx_vex(repo, rows)
    )
    return Response(
        content=json.dumps(document, ensure_ascii=False), media_type=_VEX_MEDIA_TYPES[format],
    )
