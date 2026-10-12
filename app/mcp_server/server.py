"""サイバー攻撃情報 API のリモート MCP サーバー（Streamable HTTP、`/mcp`）。

AI エージェントが API を扱いやすいよう、読み取り系の REST エンドポイントを MCP ツールとして
公開する。このモジュールは MCP サーバー（ASGI アプリとライフサイクル）の組み立てだけを担う。
ツールの定義は `tools/`（公開情報・非公開情報・接続確認）、REST への窓口と認可の検証は
`gateway.RestGateway` にある。ツールは REST をプロセス内（ASGI）で呼ぶ薄い層のため、
REST と MCP の挙動が必ず一致し、DEPSCAN / CODESCAN の「本人所有リポジトリのみ」の絞り込みも
REST 側の実装がそのまま効く。

セキュリティ（他の人に自分のリポジトリを見せない）:
- 公開情報（KEV / OSV / JVN）: 認証済みの全主体が参照できる
- 非公開情報（DEPSCAN / CODESCAN）: admin（API_KEY）か、GitHub ログインで発行した MCP
  トークンを持つ user のみ。user には REST が本人所有リポジトリのみに強制的に絞る。
  さらに多層防御として、応答に他人のリポジトリが混じっていたら（REST の絞り込みの不具合など）
  応答を返さず失敗させる（fail closed）
- 管理系（/admin/*）や書き込み系は一切ツール化しない（読み取り専用の GET のみ）
"""
import logging
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager

from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.database import SessionLocal
from app.mcp_server.auth import McpAuthMiddleware, SessionFactory
from app.mcp_server.tools import register_all

logger = logging.getLogger(__name__)

_INSTRUCTIONS = (
    "米 CISA KEV・OSV・JVN の脆弱性情報と、自分のリポジトリの依存ライブラリ脆弱性（DEPSCAN）・"
    "コード脆弱性（CODESCAN）を参照する読み取り専用ツール群。"
    "DEPSCAN / CODESCAN は GitHub ログインで発行した MCP トークンが必要で、"
    "トークンの持ち主が所有するリポジトリのみ参照できる。"
)


class McpServer:
    """FastAPI アプリに組み込む MCP サーバー（ASGI アプリとライフサイクルを束ねる）。

    MCP のセッションマネージャーは 1 インスタンスにつき `run()` を 1 回しか呼べないため、
    アプリの lifespan が開始されるたびに MCP サーバーを作り直す（アプリの再起動や、
    lifespan を何度も回すテストでも壊れないようにするため）。lifespan 外のリクエストは 503 を返す。
    """

    def __init__(self, session_factory: SessionFactory = SessionLocal) -> None:
        """session_factory: トークン台帳（失効確認）の DB セッション。テストでは差し替える。"""
        self._inner: ASGIApp | None = None
        self.asgi: ASGIApp = McpAuthMiddleware(self._dispatch, session_factory)

    @staticmethod
    def _build() -> tuple[FastMCP, ASGIApp]:
        mcp = FastMCP(
            "cyberattack-info-api",
            instructions=_INSTRUCTIONS,
            # ステートレス + JSON 応答: セッションをサーバーに持たず、再起動や複数台構成でも壊れない
            stateless_http=True,
            json_response=True,
            streamable_http_path="/mcp",
            # DNS リバインディング対策は localhost 向けサーバーのためのもの。本サーバーは
            # 公開ドメインで稼働し、全リクエストで認証を必須にしているため無効化する
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        )
        register_all(mcp)
        return mcp, mcp.streamable_http_app()

    async def _dispatch(self, scope: Scope, receive: Receive, send: Send) -> None:
        inner = self._inner
        if inner is None:
            await JSONResponse({"detail": "MCP server is not running."}, status_code=503)(
                scope, receive, send,
            )
            return
        await inner(scope, receive, send)

    def lifespan(self) -> AbstractAsyncContextManager[None]:
        """MCP サーバーを起動・終了するコンテキスト（アプリの lifespan 内で使う）。"""

        @asynccontextmanager
        async def _run() -> AsyncIterator[None]:
            mcp, inner = self._build()
            async with mcp.session_manager.run():
                self._inner = inner
                try:
                    yield
                finally:
                    self._inner = None

        return _run()

    def mount(self, app: FastAPI) -> None:
        """`/mcp` を FastAPI アプリに登録する。

        Mount だと `/mcp` が `/mcp/` へリダイレクトされるため、Route で直接つなぐ。
        """
        app.router.routes.append(
            Route("/mcp", endpoint=self.asgi, methods=["GET", "POST", "DELETE"]),
        )
