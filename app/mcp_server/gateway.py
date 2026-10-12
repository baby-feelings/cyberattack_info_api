"""MCP ツールが、アプリ自身の REST エンドポイントを呼ぶための窓口（`RestGateway`）。

ツールは検索・検証・シリアライズのロジックを複製せず、REST をプロセス内（ASGI）で呼ぶ薄い層にする。
REST と MCP の挙動が必ず一致し、DEPSCAN / CODESCAN の「本人所有リポジトリのみ」の絞り込みも
REST 側の実装がそのまま効く。ここには、その呼び出しに必要な次の処理をまとめる。

- 呼び出し元（`Principal`）の取り出し（無ければ fail closed）
- 権限に応じた認証ヘッダーの決定（公開情報は API_KEY、user は短命のセッショントークン）
- パラメータの整形（None を除く・`per_page` の上限）
- 応答の検証（user の応答に他人のリポジトリが混じっていたら fail closed。多層防御）
"""
import logging
from typing import Any

import httpx
from mcp.server.fastmcp import Context
from mcp.server.fastmcp.exceptions import ToolError

from app.auth.session import create_session_token
from app.core.config import settings
from app.mcp_server.auth import Principal

logger = logging.getLogger(__name__)

# AI エージェントのコンテキストを圧迫しないよう、1回の取得件数に上限を設ける
MAX_PER_PAGE = 50


def principal_of(ctx: Context) -> Principal:
    """認証ミドルウェアが載せた呼び出し元を取り出す（無ければ fail closed）。"""
    request = ctx.request_context.request
    principal = getattr(getattr(request, "state", None), "principal", None)
    if not isinstance(principal, Principal):
        raise ToolError("認証情報を確認できませんでした。")
    return principal


def credentials_for(principal: Principal, *, private: bool) -> dict[str, str]:
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


def enforce_owner(principal: Principal, payload: dict[str, Any]) -> None:
    """user の応答に他人のリポジトリが混じっていないことを検証する（多層防御・fail closed）。"""
    if principal.kind != "user":
        return
    prefix = f"{principal.username}/"
    rows = [*payload.get("data", []), *payload.get("repos", [])]
    if any(not str(row.get("repo_full_name", "")).startswith(prefix) for row in rows):
        logger.error("MCP owner isolation violated for user=%s", principal.username)
        raise ToolError("アクセス権のないデータが含まれていたため、応答を返せません。")


def clean_params(params: dict[str, Any]) -> dict[str, Any]:
    """None のパラメータを除く。per_page は上限を超えないようにする。"""
    cleaned = {k: v for k, v in params.items() if v is not None}
    if "per_page" in cleaned:
        cleaned["per_page"] = max(1, min(int(cleaned["per_page"]), MAX_PER_PAGE))
    return cleaned


class RestGateway:
    """1回のツール呼び出しに対応する、REST への窓口（呼び出し元の権限を保持する）。"""

    def __init__(self, ctx: Context) -> None:
        self._ctx = ctx
        self.principal = principal_of(ctx)

    async def get(
        self, path: str, params: dict[str, Any] | None = None, *, private: bool = False,
    ) -> Any:
        """アプリ自身の REST エンドポイント（GET）をプロセス内で呼び、JSON を返す。"""
        headers = credentials_for(self.principal, private=private)
        # MCP のサブアプリ内では request.app が MCP 自身を指すため、認証ミドルウェアが控えた
        # 外側の FastAPI アプリ（REST のルートを持つ）を使う
        request = self._ctx.request_context.request
        if request is None:
            raise ToolError("リクエスト情報を確認できませんでした。")
        app = request.state.root_app
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://mcp.internal",
        ) as client:
            resp = await client.get(path, params=clean_params(params or {}), headers=headers)
        if resp.status_code == 404:
            raise ToolError("該当するデータが見つかりませんでした。")
        if resp.status_code == 403:
            raise ToolError("このデータへのアクセス権がありません。")
        if resp.status_code != 200:
            logger.warning("MCP internal call failed: %s -> %s", path, resp.status_code)
            raise ToolError(f"データの取得に失敗しました（HTTP {resp.status_code}）。")
        payload = resp.json()
        if private and isinstance(payload, dict):
            enforce_owner(self.principal, payload)
        return payload
