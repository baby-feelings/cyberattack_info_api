"""接続確認用のツール（認証状態の確認）。REST は呼ばない。"""
from typing import Any

from mcp.server.fastmcp import Context, FastMCP

from app.mcp_server.gateway import principal_of


def register(mcp: FastMCP) -> None:
    """接続確認用のツールを登録する。"""

    @mcp.tool()
    async def whoami(ctx: Context) -> dict[str, Any]:
        """現在の認証状態（権限レベルと、参照できる範囲）を返す。接続確認用。"""
        principal = principal_of(ctx)
        scope = {
            "admin": "すべて",
            "public": "KEV / OSV / JVN の公開情報のみ",
            "user": f"公開情報 + {principal.username} が所有するリポジトリの DEPSCAN / CODESCAN",
        }[principal.kind]
        return {"access": principal.kind, "username": principal.username, "scope": scope}
