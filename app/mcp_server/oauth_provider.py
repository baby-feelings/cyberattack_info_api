"""MCP サーバーの OAuth 2.1 認可サーバー実装（`OAuthAuthorizationServerProvider`、Issue #303）。

SDK（`mcp.server.auth`）が `/authorize`・`/token`・`/register`・`/revoke` とメタデータを
提供し、ここでは保存層と判断だけを担う。段階的に実装している:

- PR1: クライアントの動的登録・取得
- PR2: `/authorize` → 同意画面（`oauth_consent`）→ GitHub ログイン → 認可コード
  → `/token`（PKCE は SDK が検証）。アクセストークンは既存の台帳（`mcp_tokens`）へ発行する（1時間）
- PR3（本ファイル）: リフレッシュトークン（30日。使うたびに交換するローテーションで、使用済みの
  再提示は盗用の疑いとして系統ごと失効。`oauth_refresh`）と、`/revoke` による失効
"""
import logging
from collections.abc import Callable
from datetime import UTC, datetime

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

from app.mcp_server import oauth_clients, oauth_flow, oauth_refresh
from app.mcp_server.mcp_token import verify_mcp_token
from app.mcp_server.mcp_token_store import as_utc, issue_oauth_token, revoke_oauth_tokens
from app.mcp_server.models import McpToken

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

        def _exchange() -> tuple[str, str]:
            with self._session_factory() as db:
                # 先に消費する。同じコードを同時に2回交換しても、成功するのは片方だけ
                if not oauth_flow.consume_code(db, authorization_code.code):
                    raise TokenError(
                        "invalid_grant", "authorization code is invalid or already used",
                    )
                token, _row = issue_oauth_token(
                    db, username, client_id, oauth_flow.ACCESS_TOKEN_TTL,
                )
                # 最初の認可: 新しい系統のリフレッシュトークンも発行する
                refresh = oauth_refresh.issue(
                    db, client_id, username, " ".join(authorization_code.scopes),
                    authorization_code.resource,
                )
                return token, refresh

        access_token, refresh_token = await run_in_threadpool(_exchange)
        return OAuthToken(
            access_token=access_token,
            expires_in=int(oauth_flow.ACCESS_TOKEN_TTL.total_seconds()),
            scope=" ".join(authorization_code.scopes),
            refresh_token=refresh_token,
        )

    # --- リフレッシュ（ローテーション）---

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str,
    ) -> RefreshToken | None:
        """そのクライアントの有効なリフレッシュトークンを返す。使用済みの再提示は系統ごと失効。"""
        client_id = client.client_id
        if client_id is None:
            return None

        def _load() -> RefreshToken | None:
            with self._session_factory() as db:
                row = oauth_refresh.find_usable(db, refresh_token, client_id)
                if row is None:
                    return None
                return RefreshToken(
                    token=refresh_token,
                    client_id=row.client_id,
                    scopes=row.scope.split(),
                    expires_at=int(as_utc(row.expires_at).timestamp()),
                    resource=row.resource,
                    subject=row.username,
                )

        return await run_in_threadpool(_load)

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list[str],
    ) -> OAuthToken:
        """リフレッシュトークンを使用済みにし、新しいアクセストークンとリフレッシュトークンを発行する。

        スコープは元の認可の範囲内に限る（広げられない）。
        """
        username = refresh_token.subject
        client_id = client.client_id
        if not username or client_id is None:
            raise TokenError("invalid_grant", "refresh token is invalid")
        if scopes and not set(scopes) <= set(refresh_token.scopes):
            raise TokenError("invalid_scope", "scope exceeds the original grant")
        use_scopes = scopes or refresh_token.scopes

        def _exchange() -> tuple[str, str]:
            with self._session_factory() as db:
                row = oauth_refresh.find_usable(db, refresh_token.token, client_id)
                # 使用済みにできた（条件付き UPDATE の件数で判定）ときだけ新しいトークンを発行する。
                # 同じトークンを同時に2回交換しても、成功するのは片方だけ
                if row is None or not oauth_refresh.rotate(db, row):
                    raise TokenError("invalid_grant", "refresh token is invalid or already used")
                access, _ledger = issue_oauth_token(
                    db, username, client_id, oauth_flow.ACCESS_TOKEN_TTL,
                )
                refresh = oauth_refresh.issue(
                    db, client_id, username, " ".join(use_scopes), row.resource,
                    family_id=row.family_id,
                )
                return access, refresh

        access_token, new_refresh = await run_in_threadpool(_exchange)
        return OAuthToken(
            access_token=access_token,
            expires_in=int(oauth_flow.ACCESS_TOKEN_TTL.total_seconds()),
            scope=" ".join(use_scopes),
            refresh_token=new_refresh,
        )

    # --- アクセストークンの取得・失効（/revoke）---

    async def load_access_token(self, token: str) -> AccessToken | None:
        """OAuth で発行された有効なアクセストークンなら返す（手動発行・失効済みは None）。"""
        claims = verify_mcp_token(token)
        if claims is None:
            return None

        def _load() -> AccessToken | None:
            with self._session_factory() as db:
                row = db.get(McpToken, claims.token_id)
                if (
                    row is None or row.username != claims.username
                    or row.revoked_at is not None or row.oauth_client_id is None
                ):
                    return None
                return AccessToken(
                    token=token,
                    client_id=row.oauth_client_id,
                    scopes=[SCOPE],
                    expires_at=int(as_utc(row.expires_at).timestamp()),
                    subject=row.username,
                )

        return await run_in_threadpool(_load)

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        """トークンを失効する（RFC 7009）。

        リフレッシュトークンなら、そのクライアントへの本人の許可をすべて取り消す
        （リフレッシュトークン全系統と、発行済みのアクセストークン）。
        アクセストークンなら、そのトークン1つだけを失効する。
        """
        username = token.subject
        if not username:
            return

        def _revoke() -> None:
            with self._session_factory() as db:
                if isinstance(token, RefreshToken):
                    oauth_refresh.revoke_client_grants(db, username, token.client_id)
                    revoke_oauth_tokens(db, username, token.client_id)
                    return
                claims = verify_mcp_token(token.token)
                row = db.get(McpToken, claims.token_id) if claims else None
                if row is not None and row.username == username and row.revoked_at is None:
                    row.revoked_at = datetime.now(UTC)
                    db.commit()

        await run_in_threadpool(_revoke)
