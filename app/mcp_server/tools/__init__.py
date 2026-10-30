"""MCP ツールの登録（公開情報・非公開情報・セキュリティ態勢・接続確認の4グループ）。

読み取り専用の GET だけを公開する。管理系（/admin/*）や書き込み系は一切ツール化しない。
ツールを足すときは、該当するグループのモジュールに追加する（新しいグループなら `register` を
持つモジュールを作り、ここに1行足す）。
"""
from mcp.server.fastmcp import FastMCP

from app.mcp_server.tools import identity, posture, private, public


def register_all(mcp: FastMCP) -> None:
    """すべてのツールを登録する。"""
    public.register(mcp)
    private.register(mcp)
    posture.register(mcp)
    identity.register(mcp)
