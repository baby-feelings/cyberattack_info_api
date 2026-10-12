"""MCP サーバーの OAuth 2.1 認可サーバー実装（`OAuthAuthorizationServerProvider`、Issue #303）。

SDK（`mcp.server.auth`）が `/authorize`・`/token`・`/register`・`/revoke` とメタデータを
提供し、ここでは保存層と判断だけを担う。段階的に実装している:

- PR1: クライアントの動的登録・取得
- PR2（本ファイル）: `/authorize` → 同意画面（`oauth_consent`）→ GitHub ログイン → 認可コード
  → `/token`（PKCE は SDK が検証）。アクセストークンは既存の台帳（`mcp_tokens`）へ発行する
  （1時間）。リフレッシュトークンは未対応（期限が切れたら再認可）
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

from app.auth.mcp_token_store import as_utc, issue_oauth_token
from app.mcp_server import oauth_clients, oauth_flow

logger = logging.getLogger(__name__)

SessionFactory = Callable[[], Session]

# 付与するスコープは読み取り専用の 1 種類のみ
SCOPE = "mcp:read"
# 同意画面のパス（`/authorize` の戻り先。ルート定義は oauth_consent）
CONSENT_PATH = "/oauth/consent"


class McpOAuthProvider:
    """DB（`oauth_clients`・`oauth_authorizations`・`mcp_tokens`）を保存先とする認可サーバー。"""

    def __init__(self, session_factory: SessionFactory, issuer: str) -> None:
        self._session_factory = session_factory
        self._issuer = issuer.rstrip("/")

    # --- クライアント ---

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

    # --- 認可（同意画面へ）---

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams,
    ) -> str:
        """認可リクエストを保存し、同意画面の URL を返す（SDK がそこへ 302 でリダイレクトする）。

        スコープと resource（RFC 8707）を検証する。この時点ではまだ誰も認可していない。
        """
        scopes = params.scopes or [SCOPE]
        if set(scopes) - {SCOPE}:
            raise AuthorizeError("invalid_scope", f"only '{SCOPE}' is supported")
        if params.resource is not None and params.resource.rstrip("/") != f"{self._issuer}/mcp":
            raise AuthorizeError("invalid_request", "unknown resource")
        client_id = client.client_id
        if client_id is None:
            raise AuthorizeError("invalid_request", "client is not registered")

        def _create() -> str:
            with self._session_factory() as db:
                request_id = oauth_flow.create_request(db, client_id, params, scopes)
                oauth_clients.touch_client(db, client_id)
                return request_id

        request_id = await run_in_threadpool(_create)
        return f"{self._issuer}{CONSENT_PATH}?request_id={request_id}"

    # --- トークン交換 ---

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str,
    ) -> AuthorizationCode | None:
        """認可コードを取得する。別クライアント宛て・期限切れ・未発行は None（invalid_grant）。"""

        def _load() -> AuthorizationCode | None:
            with self._session_factory() as db:
                row = oauth_flow.find_by_code(db, authorization_code)
                if row is None or row.client_id != client.client_id or row.username is None:
                    return None
                return AuthorizationCode(
                    code=authorization_code,
                    scopes=row.scope.split(),
                    expires_at=as_utc(row.expires_at).timestamp(),
                    client_id=row.client_id,
                    code_challenge=row.code_challenge,
                    redirect_uri=row.redirect_uri,  # type: ignore[arg-type]
                    redirect_uri_provided_explicitly=row.redirect_uri_provided_explicitly,
                    resource=row.resource,
                    subject=row.username,
                )

        return await run_in_threadpool(_load)

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        """認可コードを使用済みにして、アクセストークン（台帳に記録される JWT）を発行する。"""
        username = authorization_code.subject
        client_id = client.client_id
        if not username or client_id is None:
            raise TokenError("invalid_grant", "authorization code is invalid")

        def _exchange() -> str:
            with self._session_factory() as db:
                # 先に消費する。同じコードを同時に2回交換しても、成功するのは片方だけ
                if not oauth_flow.consume_code(db, authorization_code.code):
                    raise TokenError(
                        "invalid_grant", "authorization code is invalid or already used",
                    )
                token, _row = issue_oauth_token(
                    db, username, client_id, oauth_flow.ACCESS_TOKEN_TTL,
                )
                return token

        access_token = await run_in_threadpool(_exchange)
        return OAuthToken(
            access_token=access_token,
            expires_in=int(oauth_flow.ACCESS_TOKEN_TTL.total_seconds()),
            scope=" ".join(authorization_code.scopes),
        )

    # --- リフレッシュ・失効（PR3 で実装。それまでは対象なし）---

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str,
    ) -> RefreshToken | None:
        return None

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str],
    ) -> OAuthToken:
        raise TokenError("invalid_grant", "refresh tokens are not supported yet")

    async def load_access_token(self, token: str) -> AccessToken | None:
        return None

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        return None
