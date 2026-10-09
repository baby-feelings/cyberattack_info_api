"""MCP エンドポイント（/mcp）の認証。

呼び出し元を3種類の主体（Principal）に分類し、ツール側が権限に応じて振る舞いを変える。

- admin : `X-API-KEY` = API_KEY。すべて参照できる（運用者本人）
- public: `X-API-KEY` = PUBLIC_API_KEY。KEV / OSV / JVN の公開情報のみ
- user  : `Authorization: Bearer <MCPトークン>`。公開情報 + 自分が所有する
          リポジトリの DEPSCAN / CODESCAN（署名・期限に加え、台帳で失効していないことも確認する）

PUBLIC_API_KEY はダッシュボードの JS バンドルに含まれる前提の鍵（公開情報の読み取り専用）の
ため、これだけで非公開情報（リポジトリ名・脆弱箇所）が見えてはならない。
"""
import hmac
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from app.auth.mcp_token import McpClaims, verify_mcp_token
from app.auth.mcp_token_store import is_usable
from app.core.config import settings

logger = logging.getLogger(__name__)

PrincipalKind = Literal["admin", "public", "user"]


@dataclass(frozen=True)
class Principal:
    """認証済みの呼び出し元。`username` は kind == "user" のときのみ設定される。"""

    kind: PrincipalKind
    username: str | None = None


SessionFactory = Callable[[], Session]


def _token_is_usable(session_factory: SessionFactory, claims: McpClaims) -> bool:
    """台帳で、トークンが失効していないことを確認する（DB 障害時は fail closed で拒否）。"""
    try:
        with session_factory() as db:
            return is_usable(db, claims)
    except SQLAlchemyError:
        logger.exception("MCP token ledger lookup failed")
        return False


async def authenticate(headers: Headers, session_factory: SessionFactory) -> Principal | None:
    """リクエストヘッダーから呼び出し元を判定する。認証失敗なら None。"""
    api_key = headers.get("x-api-key")
    if api_key:
        if hmac.compare_digest(api_key, settings.API_KEY):
            return Principal("admin")
        if settings.PUBLIC_API_KEY and hmac.compare_digest(api_key, settings.PUBLIC_API_KEY):
            return Principal("public")

    authorization = headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        claims = verify_mcp_token(authorization[len("bearer "):].strip())
        # 台帳の確認は同期 DB アクセスのため、イベントループを塞がないようスレッドで実行する
        if claims is not None and await run_in_threadpool(
            _token_is_usable, session_factory, claims,
        ):
            return Principal("user", claims.username)
    return None


class McpAuthMiddleware:
    """/mcp への HTTP リクエストを認証し、主体を request.state に載せる ASGI ミドルウェア。"""

    def __init__(self, app: ASGIApp, session_factory: SessionFactory) -> None:
        self.app = app
        self.session_factory = session_factory

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        principal = await authenticate(Headers(scope=scope), self.session_factory)
        if principal is None:
            logger.warning("Unauthorized MCP access attempt")
            body = json.dumps({"detail": "Invalid or missing credentials."}).encode()
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"www-authenticate", b"Bearer"),
                ],
            })
            await send({"type": "http.response.body", "body": body})
            return

        # Starlette の Request.state は scope["state"] を参照する。MCP のサブアプリ内では
        # request.app が MCP 自身を指すため、REST を呼ぶための外側の FastAPI アプリもここで控える
        state = scope.setdefault("state", {})
        state["principal"] = principal
        state["root_app"] = scope.get("app")
        await self.app(scope, receive, send)
