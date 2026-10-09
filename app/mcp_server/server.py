"""サイバー攻撃情報 API のリモート MCP サーバー（Streamable HTTP、`/mcp`）。

AI エージェントが API を扱いやすいよう、読み取り系の REST エンドポイントを MCP ツールとして
公開する。ツールは検索・検証・シリアライズのロジックを複製せず、アプリ自身の REST
エンドポイントをプロセス内（ASGI）で呼ぶ薄い層にする。REST と MCP の挙動が必ず一致し、
DEPSCAN / CODESCAN の「本人所有リポジトリのみ」の絞り込みも REST 側の実装がそのまま効く。

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
from typing import Any

import httpx
from fastapi import FastAPI
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Receive, Scope, Send

from app.auth.session import create_session_token
from app.core.config import settings
from app.mcp_server.auth import McpAuthMiddleware, Principal

logger = logging.getLogger(__name__)

# AI エージェントのコンテキストを圧迫しないよう、1回の取得件数に上限を設ける
MAX_PER_PAGE = 50

_INSTRUCTIONS = (
    "米 CISA KEV・OSV・JVN の脆弱性情報と、自分のリポジトリの依存ライブラリ脆弱性（DEPSCAN）・"
    "コード脆弱性（CODESCAN）を参照する読み取り専用ツール群。"
    "DEPSCAN / CODESCAN は GitHub ログインで発行した MCP トークンが必要で、"
    "トークンの持ち主が所有するリポジトリのみ参照できる。"
)


def _principal(ctx: Context) -> Principal:
    """認証ミドルウェアが載せた呼び出し元を取り出す（無ければ fail closed）。"""
    request = ctx.request_context.request
    principal = getattr(getattr(request, "state", None), "principal", None)
    if not isinstance(principal, Principal):
        raise ToolError("認証情報を確認できませんでした。")
    return principal


def _credentials(principal: Principal, *, private: bool) -> dict[str, str]:
    """REST をプロセス内で呼ぶときの認証ヘッダーを、権限に応じて決める。"""
    if not private:
        # 公開情報の読み取り。ツールは GET の許可リストのみなので、内部では API_KEY を使う
        return {"X-API-KEY": settings.API_KEY}
    if principal.kind == "admin":
        return {"X-API-KEY": settings.API_KEY}
    if principal.kind == "user" and principal.username:
        # REST 側が本人所有リポジトリのみに絞る。短命のセッショントークンを内部で発行して渡す
        return {"Authorization": f"Bearer {create_session_token(principal.username)}"}
    raise ToolError(
        "DEPSCAN / CODESCAN の参照には、GitHub ログインで発行した MCP トークンが必要です。"
        "（ダッシュボードのメニューから発行し、Authorization: Bearer で渡してください）"
    )


def _enforce_owner(principal: Principal, payload: dict[str, Any]) -> None:
    """user の応答に他人のリポジトリが混じっていないことを検証する（多層防御・fail closed）。"""
    if principal.kind != "user":
        return
    prefix = f"{principal.username}/"
    rows = [*payload.get("data", []), *payload.get("repos", [])]
    if any(not str(row.get("repo_full_name", "")).startswith(prefix) for row in rows):
        logger.error("MCP owner isolation violated for user=%s", principal.username)
        raise ToolError("アクセス権のないデータが含まれていたため、応答を返せません。")


def _clean(params: dict[str, Any]) -> dict[str, Any]:
    """None のパラメータを除く。per_page は上限を超えないようにする。"""
    cleaned = {k: v for k, v in params.items() if v is not None}
    if "per_page" in cleaned:
        cleaned["per_page"] = max(1, min(int(cleaned["per_page"]), MAX_PER_PAGE))
    return cleaned


async def _get(
    ctx: Context, path: str, params: dict[str, Any] | None = None, *, private: bool = False,
) -> Any:
    """アプリ自身の REST エンドポイント（GET）をプロセス内で呼び、JSON を返す。"""
    principal = _principal(ctx)
    headers = _credentials(principal, private=private)
    # MCP のサブアプリ内では request.app が MCP 自身を指すため、認証ミドルウェアが控えた
    # 外側の FastAPI アプリ（REST のルートを持つ）を使う
    request = ctx.request_context.request
    if request is None:
        raise ToolError("リクエスト情報を確認できませんでした。")
    app = request.state.root_app
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://mcp.internal",
    ) as client:
        resp = await client.get(path, params=_clean(params or {}), headers=headers)
    if resp.status_code == 404:
        raise ToolError("該当するデータが見つかりませんでした。")
    if resp.status_code == 403:
        raise ToolError("このデータへのアクセス権がありません。")
    if resp.status_code != 200:
        logger.warning("MCP internal call failed: %s -> %s", path, resp.status_code)
        raise ToolError(f"データの取得に失敗しました（HTTP {resp.status_code}）。")
    payload = resp.json()
    if private and isinstance(payload, dict):
        _enforce_owner(principal, payload)
    return payload


def _register_tools(mcp: FastMCP) -> None:
    """ツールを登録する（読み取り専用の GET のみ。管理系は含めない）。"""

    # ── 公開情報（KEV / OSV / JVN） ──────────────────────────────

    @mcp.tool()
    async def search_kev(
        ctx: Context,
        search: str | None = None,
        vendor: str | None = None,
        product: str | None = None,
        min_epss: float | None = None,
        page: int = 1,
        per_page: int = 20,
    ) -> dict[str, Any]:
        """CISA KEV（実際に悪用が確認された脆弱性）を検索する。

        search はベンダー名・製品名の部分一致、min_epss は悪用確率(0〜1)の下限。
        新しく追加された順に返す。
        """
        return await _get(ctx, "/api/vulnerabilities", {
            "search": search, "vendor": vendor, "product": product,
            "min_epss": min_epss, "page": page, "per_page": per_page,
        })

    @mcp.tool()
    async def get_recent_kev(ctx: Context, days: int = 30) -> dict[str, Any]:
        """直近 days 日（1〜365）に CISA KEV へ追加された脆弱性を、新しい順に返す。

        件数が多い期間でもコンテキストを圧迫しないよう、返すのは新しい順に最大 50 件。
        全体の件数は total で分かる（それ以上は search_kev でページを送って取得する）。
        """
        items = await _get(ctx, "/api/vulnerabilities/recent", {"days": days})
        return {"total": len(items), "data": items[:MAX_PER_PAGE]}

    @mcp.tool()
    async def get_kev(ctx: Context, cve_id: str) -> dict[str, Any]:
        """CVE ID（例: CVE-2024-3400）を指定して、KEV の脆弱性の詳細を1件取得する。"""
        return await _get(ctx, f"/api/vulnerabilities/{cve_id}")

    @mcp.tool()
    async def search_osv(
        ctx: Context,
        search: str | None = None,
        ecosystem: str | None = None,
        severity: str | None = None,
        days: int = 30,
        page: int = 1,
        per_page: int = 20,
    ) -> dict[str, Any]:
        """OSV（オープンソースの脆弱性）を検索する。

        ecosystem は PyPI / npm など、severity は CRITICAL / HIGH / MEDIUM / LOW、
        days は直近何日に更新されたものか（1〜365）。
        """
        return await _get(ctx, "/api/osv", {
            "search": search, "ecosystem": ecosystem, "severity": severity,
            "days": days, "page": page, "per_page": per_page,
        })

    @mcp.tool()
    async def search_jvn(
        ctx: Context,
        search: str | None = None,
        severity: str | None = None,
        days: int = 30,
        page: int = 1,
        per_page: int = 20,
    ) -> dict[str, Any]:
        """JVN（日本の脆弱性情報データベース）を検索する。days は直近何日に更新されたものか。"""
        return await _get(ctx, "/api/jvn", {
            "search": search, "severity": severity, "days": days,
            "page": page, "per_page": per_page,
        })

    # ── 非公開情報（DEPSCAN / CODESCAN。本人所有リポジトリのみ） ─────

    @mcp.tool()
    async def list_depscan_findings(
        ctx: Context,
        repo: str | None = None,
        severity: str | None = None,
        ecosystem: str | None = None,
        resolved: bool = False,
        page: int = 1,
        per_page: int = 20,
    ) -> dict[str, Any]:
        """自分のリポジトリで検知された、依存ライブラリの脆弱性（DEPSCAN）を返す。

        repo は "owner/repo"。resolved=False は未解決のみ。MCP トークンが必要。
        """
        return await _get(ctx, "/api/depscan", {
            "repo": repo, "severity": severity, "ecosystem": ecosystem,
            "resolved": resolved, "page": page, "per_page": per_page,
        }, private=True)

    @mcp.tool()
    async def get_depscan_stats(ctx: Context) -> dict[str, Any]:
        """自分のリポジトリの、未解決の依存ライブラリ脆弱性の件数（リポジトリ別・重要度別）。"""
        return await _get(ctx, "/api/depscan/stats", private=True)

    @mcp.tool()
    async def list_codescan_findings(
        ctx: Context,
        repo: str | None = None,
        severity: str | None = None,
        min_cvss: float | None = None,
        resolved: bool = False,
        page: int = 1,
        per_page: int = 20,
    ) -> dict[str, Any]:
        """自分のリポジトリで検知された、コードの脆弱性（CODESCAN）を返す。

        repo は "owner/repo"、resolved=False は未解決のみ、min_cvss は CVSS の下限。
        MCP トークンが必要。
        """
        return await _get(ctx, "/api/codescan", {
            "repo": repo, "severity": severity, "min_cvss": min_cvss,
            "resolved": resolved, "page": page, "per_page": per_page,
        }, private=True)

    @mcp.tool()
    async def get_codescan_stats(ctx: Context) -> dict[str, Any]:
        """自分のリポジトリの、未解決のコード脆弱性の件数（リポジトリ別・重要度別）。"""
        return await _get(ctx, "/api/codescan/stats", private=True)

    @mcp.tool()
    async def whoami(ctx: Context) -> dict[str, Any]:
        """現在の認証状態（権限レベルと、参照できる範囲）を返す。接続確認用。"""
        principal = _principal(ctx)
        scope = {
            "admin": "すべて",
            "public": "KEV / OSV / JVN の公開情報のみ",
            "user": f"公開情報 + {principal.username} が所有するリポジトリの DEPSCAN / CODESCAN",
        }[principal.kind]
        return {"access": principal.kind, "username": principal.username, "scope": scope}


class McpServer:
    """FastAPI アプリに組み込む MCP サーバー（ASGI アプリとライフサイクルを束ねる）。

    MCP のセッションマネージャーは 1 インスタンスにつき `run()` を 1 回しか呼べないため、
    アプリの lifespan が開始されるたびに MCP サーバーを作り直す（アプリの再起動や、
    lifespan を何度も回すテストでも壊れないようにするため）。lifespan 外のリクエストは 503 を返す。
    """

    def __init__(self) -> None:
        self._inner: ASGIApp | None = None
        self.asgi: ASGIApp = McpAuthMiddleware(self._dispatch)

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
        _register_tools(mcp)
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
