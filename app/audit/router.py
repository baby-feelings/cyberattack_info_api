"""監査ログの閲覧 API（管理者のみ。Issue #406）。"""
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Security
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.audit.models import AuditLog
from app.auth.api_key import require_api_key
from app.core.database import get_db

router = APIRouter(
    prefix="/api/audit-logs", tags=["audit"], dependencies=[Security(require_api_key)],
)


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    occurred_at: str
    actor: str
    action: str
    outcome: str
    status_code: int | None


class AuditLogListResponse(BaseModel):
    total: int
    data: list[AuditLogOut]


@router.get(
    "", response_model=AuditLogListResponse, summary="監査ログ（管理操作・認証・MCPトークン）",
    description="新しい順。誰が（actor）・いつ・何を（action）・結果（outcome）。IP・シークレット・"
    "リクエストの本文は、記録していない。管理者用 API キー必須。",
)
def list_audit_logs(
    db: Annotated[Session, Depends(get_db)],
    outcome: Annotated[
        str | None, Query(description="結果で絞り込み（ok/denied/throttled/error）"),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> AuditLogListResponse:
    query = db.query(AuditLog)
    if outcome:
        query = query.filter(AuditLog.outcome == outcome)
    rows = query.order_by(AuditLog.occurred_at.desc(), AuditLog.id.desc()).limit(limit).all()
    return AuditLogListResponse(
        total=len(rows),
        data=[
            AuditLogOut(
                occurred_at=r.occurred_at.isoformat(), actor=r.actor, action=r.action,
                outcome=r.outcome, status_code=r.status_code,
            ) for r in rows
        ],
    )
