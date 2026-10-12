"""OAuth 2.1 認可サーバーの判断（認可・トークン交換・リフレッシュ・失効）。

`McpOAuthProvider`（SDK の `OAuthAuthorizationServerProvider`）は async と SDK の型への変換だけを
担い、DB を使う判断はここの同期サービスに任せる。`Session` を引数に取るので、async や HTTP を
介さずに単体でテストできる。

- `AuthorizationService`: `/authorize` の検証と認可リクエストの保存、認可コードの取得と交換
- `RefreshService`: リフレッシュトークンの取得・ローテーション（使用済みの再提示は盗用の疑いとして
  系統ごと失効）・クライアントへの許可の取り消し
- `AccessTokenService`: OAuth で発行されたアクセストークンの取得と、1つだけの失効
"""
from dataclasses import dataclass
from datetime import UTC, datetime

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull
from sqlalchemy.orm import Session

from app.mcp_server.mcp_token import verify_mcp_token
from app.mcp_server.mcp_token_store import as_utc, issue_oauth_token, revoke_oauth_tokens
from app.mcp_server.models import McpToken
from app.mcp_server.oauth import clients as oauth_clients
from app.mcp_server.oauth import flow as oauth_flow
from app.mcp_server.oauth import refresh as oauth_refresh

# 付与するスコープは読み取り専用の 1 種類のみ
SCOPE = "mcp:read"
# 同意画面のパス（`/authorize` の戻り先。ルート定義は oauth_consent）
CONSENT_PATH = "/oauth/consent"


@dataclass(frozen=True)
class IssuedTokens:
    """発行したトークンの組（アクセストークンと、ローテーションしたリフレッシュトークン）。"""

    access_token: str
    refresh_token: str
    scope: str


class AuthorizationService:
    """`/authorize` と、認可コードの取得・交換。"""

    def __init__(self, issuer: str) -> None:
        self._issuer = issuer.rstrip("/")

    def begin(
        self, db: Session, client: OAuthClientInformationFull, params: AuthorizationParams,
    ) -> str:
        """認可リクエストを保存し、同意画面の URL を返す（この時点ではまだ誰も認可していない）。

        スコープと resource（RFC 8707）を検証する。
        """
        scopes = params.scopes or [SCOPE]
        if set(scopes) - {SCOPE}:
            raise AuthorizeError("invalid_scope", f"only '{SCOPE}' is supported")
        if params.resource is not None and params.resource.rstrip("/") != f"{self._issuer}/mcp":
            raise AuthorizeError("invalid_request", "unknown resource")
        client_id = client.client_id
        if client_id is None:
            raise AuthorizeError("invalid_request", "client is not registered")

        request_id = oauth_flow.create_request(db, client_id, params, scopes)
        oauth_clients.touch_client(db, client_id)
        return f"{self._issuer}{CONSENT_PATH}?request_id={request_id}"

    @staticmethod
    def load_code(db: Session, client_id: str | None, code: str) -> AuthorizationCode | None:
        """認可コードを取得する。別クライアント宛て・期限切れ・未発行は None（invalid_grant）。"""
        row = oauth_flow.find_by_code(db, code)
        if row is None or row.client_id != client_id or row.username is None:
            return None
        return AuthorizationCode(
            code=code,
            scopes=row.scope.split(),
            expires_at=as_utc(row.expires_at).timestamp(),
            client_id=row.client_id,
            code_challenge=row.code_challenge,
            redirect_uri=row.redirect_uri,  # type: ignore[arg-type]
            redirect_uri_provided_explicitly=row.redirect_uri_provided_explicitly,
            resource=row.resource,
            subject=row.username,
        )

    @staticmethod
    def exchange(
        db: Session, client_id: str | None, authorization_code: AuthorizationCode,
    ) -> IssuedTokens:
        """認可コードを使用済みにして、アクセストークン（台帳に記録される JWT）を発行する。"""
        username = authorization_code.subject
        if not username or client_id is None:
            raise TokenError("invalid_grant", "authorization code is invalid")

        # 先に消費する。同じコードを同時に2回交換しても、成功するのは片方だけ
        if not oauth_flow.consume_code(db, authorization_code.code):
            raise TokenError("invalid_grant", "authorization code is invalid or already used")
        access, _ledger = issue_oauth_token(db, username, client_id, oauth_flow.ACCESS_TOKEN_TTL)
        scope = " ".join(authorization_code.scopes)
        # 最初の認可: 新しい系統のリフレッシュトークンも発行する
        refresh = oauth_refresh.issue(db, client_id, username, scope, authorization_code.resource)
        return IssuedTokens(access, refresh, scope)


class RefreshService:
    """リフレッシュトークンの取得・ローテーション・許可の取り消し。"""

    @staticmethod
    def load(db: Session, client_id: str | None, token: str) -> RefreshToken | None:
        """そのクライアントの有効なリフレッシュトークンを返す。使用済みの再提示は系統ごと失効。"""
        if client_id is None:
            return None
        row = oauth_refresh.find_usable(db, token, client_id)
        if row is None:
            return None
        return RefreshToken(
            token=token,
            client_id=row.client_id,
            scopes=row.scope.split(),
            expires_at=int(as_utc(row.expires_at).timestamp()),
            resource=row.resource,
            subject=row.username,
        )

    @staticmethod
    def exchange(
        db: Session, client_id: str | None, refresh_token: RefreshToken, scopes: list[str],
    ) -> IssuedTokens:
        """リフレッシュトークンを使用済みにし、新しいアクセストークンとリフレッシュトークンを発行する。

        スコープは元の認可の範囲内に限る（広げられない）。
        """
        username = refresh_token.subject
        if not username or client_id is None:
            raise TokenError("invalid_grant", "refresh token is invalid")
        if scopes and not set(scopes) <= set(refresh_token.scopes):
            raise TokenError("invalid_scope", "scope exceeds the original grant")
        use_scopes = scopes or refresh_token.scopes

        row = oauth_refresh.find_usable(db, refresh_token.token, client_id)
        # 使用済みにできた（条件付き UPDATE の件数で判定）ときだけ新しいトークンを発行する。
        # 同じトークンを同時に2回交換しても、成功するのは片方だけ
        if row is None or not oauth_refresh.rotate(db, row):
            raise TokenError("invalid_grant", "refresh token is invalid or already used")
        access, _ledger = issue_oauth_token(db, username, client_id, oauth_flow.ACCESS_TOKEN_TTL)
        scope = " ".join(use_scopes)
        refresh = oauth_refresh.issue(
            db, client_id, username, scope, row.resource, family_id=row.family_id,
        )
        return IssuedTokens(access, refresh, scope)

    @staticmethod
    def revoke_all(db: Session, username: str, client_id: str) -> None:
        """そのクライアントへの本人の許可をすべて取り消す（全系統のリフレッシュトークンと発行済みアクセストークン）。"""
        oauth_refresh.revoke_client_grants(db, username, client_id)
        revoke_oauth_tokens(db, username, client_id)


class AccessTokenService:
    """OAuth で発行されたアクセストークンの取得と失効。"""

    @staticmethod
    def load(db: Session, token: str) -> AccessToken | None:
        """OAuth で発行された有効なアクセストークンなら返す（手動発行・失効済みは None）。"""
        claims = verify_mcp_token(token)
        if claims is None:
            return None
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

    @staticmethod
    def revoke(db: Session, username: str, token: str) -> None:
        """アクセストークン1つだけを失効する（本人のものだけ。失効済みなら何もしない）。"""
        claims = verify_mcp_token(token)
        row = db.get(McpToken, claims.token_id) if claims else None
        if row is not None and row.username == username and row.revoked_at is None:
            row.revoked_at = datetime.now(UTC)
            db.commit()
