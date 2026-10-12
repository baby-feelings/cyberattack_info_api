"""MCP サーバーの OAuth 2.1 認可サーバー実装（`OAuthAuthorizationServerProvider`、Issue #303）。

SDK（`mcp.server.auth`）が `/authorize`・`/token`・`/register`・`/revoke` とメタデータを提供する。
このクラスは SDK との橋渡し（async への変換・SDK の型への詰め替え・DB セッションの管理）だけを担い、
認可・トークン交換・リフレッシュ・失効の判断は `oauth_services` の同期サービスに任せる。

- クライアントの動的登録・取得: `oauth_clients`
- `/authorize` → 同意画面（`oauth_consent`）→ GitHub ログイン → 認可コード → `/token`
  （PKCE は SDK が検証。アクセストークンは既存の台帳 `mcp_tokens` へ 1 時間で発行）
- リフレッシュトークン（30日。使うたびに交換するローテーションで、使用済みの再提示は盗用の疑いとして
  系統ごと失効。`oauth_refresh`）と、`/revoke` による失効
"""
import logging
from collections.abc import Callable
from typing import TypeVar

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.mcp_server.oauth import clients as oauth_clients
from app.mcp_server.oauth import flow as oauth_flow
from app.mcp_server.oauth.services import (
    AccessTokenService,
    AuthorizationService,
    IssuedTokens,
    RefreshService,
)

logger = logging.getLogger(__name__)

SessionFactory = Callable[[], Session]

_T = TypeVar("_T")


def _to_oauth_token(issued: IssuedTokens) -> OAuthToken:
    return OAuthToken(
        access_token=issued.access_token,
        expires_in=int(oauth_flow.ACCESS_TOKEN_TTL.total_seconds()),
        scope=issued.scope,
        refresh_token=issued.refresh_token,
    )


class McpOAuthProvider:
    """DB（`oauth_clients`・`oauth_authorizations`・`mcp_tokens`）を保存先とする認可サーバー。"""

    def __init__(self, session_factory: SessionFactory, issuer: str) -> None:
        self._session_factory = session_factory
        self._authorization = AuthorizationService(issuer)
        self._refresh = RefreshService()
        self._access = AccessTokenService()

    async def _in_db(self, work: Callable[[Session], _T]) -> _T:
        """同期の処理を、DB セッションを開いてスレッドプールで実行する（ループを塞がない）。"""

        def _run() -> _T:
            with self._session_factory() as db:
                return work(db)

        return await run_in_threadpool(_run)

    # --- クライアント ---

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return await self._in_db(lambda db: oauth_clients.load_client(db, client_id))

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        # 検証・上限超過は RegistrationError（SDK が 400 で返す）
        await self._in_db(lambda db: oauth_clients.save_client(db, client_info))

    # --- 認可（同意画面へ）---

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams,
    ) -> str:
        """認可リクエストを保存し、同意画面の URL を返す（SDK がそこへ 302 でリダイレクトする）。"""
        return await self._in_db(lambda db: self._authorization.begin(db, client, params))

    # --- トークン交換 ---

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str,
    ) -> AuthorizationCode | None:
        return await self._in_db(
            lambda db: self._authorization.load_code(db, client.client_id, authorization_code),
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        issued = await self._in_db(
            lambda db: self._authorization.exchange(db, client.client_id, authorization_code),
        )
        return _to_oauth_token(issued)

    # --- リフレッシュ（ローテーション）---

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str,
    ) -> RefreshToken | None:
        return await self._in_db(
            lambda db: self._refresh.load(db, client.client_id, refresh_token),
        )

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str],
    ) -> OAuthToken:
        issued = await self._in_db(
            lambda db: self._refresh.exchange(db, client.client_id, refresh_token, scopes),
        )
        return _to_oauth_token(issued)

    # --- アクセストークンの取得・失効（/revoke）---

    async def load_access_token(self, token: str) -> AccessToken | None:
        return await self._in_db(lambda db: self._access.load(db, token))

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        """トークンを失効する（RFC 7009）。

        リフレッシュトークンなら、そのクライアントへの本人の許可をすべて取り消す。
        アクセストークンなら、そのトークン1つだけを失効する。
        """
        username = token.subject
        if not username:
            return
        if isinstance(token, RefreshToken):
            await self._in_db(lambda db: self._refresh.revoke_all(db, username, token.client_id))
        else:
            await self._in_db(lambda db: self._access.revoke(db, username, token.token))
