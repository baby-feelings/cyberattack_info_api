"""OAuth 2.1 認可サーバーのルート組み立て（Issue #303）。

`MCP_OAUTH_ISSUER` が空なら何も公開しない（従来の貼り付け方式のトークンのみの動作を保つ）。
設定されている場合だけ、SDK の認可ルート（メタデータ・/authorize・/token・/register・/revoke）と、
保護リソースのメタデータ（`/.well-known/oauth-protected-resource/mcp`）を FastAPI に追加する。
"""
import logging

from fastapi import FastAPI
from mcp.server.auth.routes import create_auth_routes, create_protected_resource_routes
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from pydantic import AnyHttpUrl

from app.core.config import settings
from app.core.database import SessionLocal
from app.mcp_server.oauth_provider import McpOAuthProvider

logger = logging.getLogger(__name__)

# 付与するスコープは読み取り専用の 1 種類のみ（書き込み・管理系は対象外）
SCOPE = "mcp:read"


def mount_oauth_routes(app: FastAPI, issuer: str | None = None) -> bool:
    """OAuth のルートを追加する。無効（issuer 未設定）なら追加せず False を返す。"""
    issuer = (issuer if issuer is not None else settings.MCP_OAUTH_ISSUER).rstrip("/")
    if not issuer:
        return False

    issuer_url = AnyHttpUrl(issuer)
    provider = McpOAuthProvider(SessionLocal)
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
    logger.info("MCP OAuth endpoints enabled (issuer=%s)", issuer)
    return True
