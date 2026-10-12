"""OAuth 2.1 認可サーバーのルート組み立て（Issue #303）。

`MCP_OAUTH_ISSUER` が空なら何も公開しない（従来の貼り付け方式のトークンのみの動作を保つ）。
設定されている場合だけ、SDK の認可ルート（メタデータ・/authorize・/token・/register・/revoke）と、
保護リソースのメタデータ（`/.well-known/oauth-protected-resource/mcp`）を FastAPI に追加する。
"""
import logging
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import Response
from mcp.server.auth.routes import create_auth_routes, create_protected_resource_routes
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from pydantic import AnyHttpUrl
from sqlalchemy.orm import Session

from app.auth import external_login
from app.core.config import settings
from app.core.database import SessionLocal
from app.mcp_server.oauth_consent import BROWSER_COOKIE, build_consent_router, complete_github_login
from app.mcp_server.oauth_flow import decode_state
from app.mcp_server.oauth_provider import SCOPE, McpOAuthProvider

logger = logging.getLogger(__name__)


def _complete_github_login(db: Session, request_id: str, code: str, request: Request) -> Response:
    """GitHub のコールバック（MCP 用の state）を、同意画面のブラウザ Cookie つきで完了する。"""
    return complete_github_login(db, request_id, code, request.cookies.get(BROWSER_COOKIE))


def mount_oauth_routes(app: FastAPI, issuer: str | None = None) -> bool:
    """OAuth のルートを追加する。無効（issuer 未設定）なら追加せず False を返す。"""
    issuer = (issuer if issuer is not None else settings.MCP_OAUTH_ISSUER).rstrip("/")
    if not issuer:
        return False

    # 同意画面を開いたブラウザの Cookie を、GitHub から戻るコールバックでも確認する。
    # Cookie はホスト単位のため、issuer とコールバックのホストが違うと確認できず、攻撃者の
    # 認可リクエストに被害者の本人確認を紐づける攻撃を防げない。誤設定のまま起動させない
    callback_host = urlsplit(settings.API_BASE_URL_FOR_OAUTH).netloc
    if urlsplit(issuer).netloc != callback_host:
        raise ValueError(
            "MCP_OAUTH_ISSUER must use the same host as API_BASE_URL_FOR_OAUTH "
            f"({callback_host}) so the consent browser cookie reaches the GitHub callback",
        )

    issuer_url = AnyHttpUrl(issuer)
    provider = McpOAuthProvider(SessionLocal, issuer)
    routes = create_auth_routes(
        provider=provider,
        issuer_url=issuer_url,
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE],
        ),
        revocation_options=RevocationOptions(enabled=True),
    )
    routes += create_protected_resource_routes(
        resource_url=AnyHttpUrl(f"{issuer}/mcp"),
        authorization_servers=[issuer_url],
        scopes_supported=[SCOPE],
        resource_name="cyberattack-info MCP",
    )
    app.router.routes.extend(routes)
    # 同意画面（/oauth/consent）。GitHub ログイン後の認可コード発行は /auth/github/callback が担う
    app.include_router(build_consent_router(SessionLocal))
    # GitHub ログインの戻り（/auth/github/callback）のうち MCP 用の state を、こちらで引き受ける
    external_login.register(external_login.ExternalLoginFlow(
        name="mcp-oauth", decode_state=decode_state, complete=_complete_github_login,
    ))
    logger.info("MCP OAuth endpoints enabled (issuer=%s)", issuer)
    return True
