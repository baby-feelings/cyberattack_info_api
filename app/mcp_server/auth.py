"""MCP エンドポイント（/mcp）の認証。

呼び出し元を3種類の主体（Principal）に分類し、ツール側が権限に応じて振る舞いを変える。

- admin : `X-API-KEY` = API_KEY。すべて参照できる（運用者本人）
- public: `X-API-KEY` = PUBLIC_API_KEY。KEV / OSV / JVN の公開情報のみ
- user  : `Authorization: Bearer <MCPトークン>`。公開情報 + 自分が所有する
          リポジトリの DEPSCAN / CODESCAN

PUBLIC_API_KEY はダッシュボードの JS バンドルに含まれる前提の鍵（公開情報の読み取り専用）の
ため、これだけで非公開情報（リポジトリ名・脆弱箇所）が見えてはならない。
"""
import hmac
import json
import logging
from dataclasses import dataclass
from typing import Literal

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from app.auth.mcp_token import verify_mcp_token
from app.core.config import settings

logger = logging.getLogger(__name__)

PrincipalKind = Literal["admin", "public", "user"]


@dataclass(frozen=True)
class Principal:
    """認証済みの呼び出し元。`username` は kind == "user" のときのみ設定される。"""

    kind: PrincipalKind
    username: str | None = None


def authenticate(headers: Headers) -> Principal | None:
    """リクエストヘッダーから呼び出し元を判定する。認証失敗なら None。"""
    api_key = headers.get("x-api-key")
    if api_key:
        if hmac.compare_digest(api_key, settings.API_KEY):
            return Principal("admin")
        if settings.PUBLIC_API_KEY and hmac.compare_digest(api_key, settings.PUBLIC_API_KEY):
            return Principal("public")

    authorization = headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        username = verify_mcp_token(authorization[len("bearer "):].strip())
        if username is not None:
            return Principal("user", username)
    return None


class McpAuthMiddleware:
    """/mcp への HTTP リクエストを認証し、主体を request.state に載せる ASGI ミドルウェア。"""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        principal = authenticate(Headers(scope=scope))
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
