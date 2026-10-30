"""監査ログの記録（関数と、ミドルウェア）・保持期間を過ぎた記録の削除。"""
import logging
from datetime import timedelta
from typing import Any

from starlette.concurrency import run_in_threadpool

from app.audit.models import AuditLog
from app.core.config import settings
from app.core.database import SessionLocal
from app.core.rate_limit import is_limited_path
from app.crawler_logs.writer import now_utc

logger = logging.getLogger(__name__)

# 変更系のメソッド（これらは、結果によらず記録する）。読み取り（GET）は、失敗したときだけ記録する
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# 明示的に（ユーザー名つきで）記録するパス。ミドルウェアでは、二重に記録しない
_EXPLICIT_PREFIXES = ("/auth/mcp-token",)
_MAX_ACTION_LENGTH = 200


def outcome_of(status: int | None) -> str:
    """HTTP ステータスから、記録する結果を決める。"""
    if status in (401, 403):
        return "denied"
    if status == 429:
        return "throttled"
    if status is not None and status >= 500:
        return "error"
    return "ok"


def record_audit(
    actor: str, action: str, outcome: str = "ok", status_code: int | None = None,
) -> None:
    """監査ログを1件記録する。失敗しても、呼び出し元の処理は止めない。"""
    try:
        with SessionLocal() as db:
            db.add(AuditLog(
                occurred_at=now_utc(), actor=actor[:100], action=action[:_MAX_ACTION_LENGTH],
                outcome=outcome, status_code=status_code,
            ))
            db.commit()
    except Exception:  # noqa: BLE001 - 監査の失敗で、本来の処理を失敗させない
        logger.exception("Failed to write audit log: %s", action)


def delete_old_audit_logs() -> int:
    """保持期間（`AUDIT_RETENTION_DAYS`）を過ぎた記録を削除する。削除した件数を返す。"""
    cutoff = now_utc() - timedelta(days=settings.AUDIT_RETENTION_DAYS)
    with SessionLocal() as db:
        deleted = db.query(AuditLog).filter(AuditLog.occurred_at < cutoff).delete(
            synchronize_session=False,
        )
        db.commit()
    logger.info("Audit logs deleted: %d (older than %s)", deleted, cutoff)
    return int(deleted)


def _actor_of(scope: dict[str, Any]) -> str:
    """誰の操作か（ヘッダーの有無だけで判定する。値は、見ない・記録しない）。"""
    names = {name for name, _ in scope.get("headers", [])}
    if b"x-api-key" in names:
        return "api-key"
    if b"authorization" in names:
        return "session"
    return "anonymous"


class AuditMiddleware:
    """ASGI ミドルウェア。管理操作・認証系の変更系の操作と、認証の失敗・拒否を記録する。"""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        path = scope.get("path", "")
        if (
            scope["type"] != "http" or not is_limited_path(path)
            or path.startswith(_EXPLICIT_PREFIXES)
        ):
            await self.app(scope, receive, send)
            return

        status: dict[str, int] = {}

        async def capture(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
            await send(message)

        await self.app(scope, receive, capture)

        code = status.get("code")
        outcome = outcome_of(code)
        if scope["method"] in _WRITE_METHODS or outcome != "ok":
            # パスだけを記録する（クエリ・ヘッダーの値・本文は、記録しない）
            await run_in_threadpool(
                record_audit, _actor_of(scope), f"{scope['method']} {path}", outcome, code,
            )
