"""MCP サーバーの OAuth 2.1 認可サーバー実装（`OAuthAuthorizationServerProvider`、Issue #303）。

SDK（`mcp.server.auth`）が `/authorize`・`/token`・`/register`・`/revoke` とメタデータを
提供し、ここでは保存層だけを担う。段階的に実装している:

- PR1（本ファイル）: クライアントの動的登録・取得。認可コードの発行（GitHub ログイン連携）と
  トークン交換は未実装で、呼ばれたら明示的なエラーを返す（未実装のまま認可が通ることはない）
- PR2: `/authorize` → 同意 → GitHub ログイン → 認可コード → `/token`
- PR3: リフレッシュトークンのローテーション・失効
"""
import logging
from collections.abc import Callable

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.mcp_server import oauth_clients

logger = logging.getLogger(__name__)

SessionFactory = Callable[[], Session]


class McpOAuthProvider:
    """DB（`oauth_clients`）を保存先とする認可サーバーのプロバイダー。"""

    def __init__(self, session_factory: SessionFactory) -> None:
        self._session_factory = session_factory

    # --- クライアント（PR1 で実装） ---

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        def _load() -> OAuthClientInformationFull | None:
            with self._session_factory() as db:
                return oauth_clients.load_client(db, client_id)

        return await run_in_threadpool(_load)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        def _save() -> None:
            with self._session_factory() as db:
                oauth_clients.save_client(db, client_info)

        # 検証・上限超過は RegistrationError（SDK が 400 で返す）
        await run_in_threadpool(_save)

    # --- 認可・トークン（PR2 以降で実装。それまでは常に拒否する） ---

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams,
    ) -> str:
        raise AuthorizeError("server_error", "authorization is not available yet")

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str,
    ) -> AuthorizationCode | None:
        return None

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        raise TokenError("invalid_grant", "authorization is not available yet")

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str,
    ) -> RefreshToken | None:
        return None

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str],
    ) -> OAuthToken:
        raise TokenError("invalid_grant", "refresh is not available yet")

    async def load_access_token(self, token: str) -> AccessToken | None:
        return None

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        return None
