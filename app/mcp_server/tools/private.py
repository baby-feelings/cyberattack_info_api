"""非公開情報（DEPSCAN / CODESCAN）を参照する MCP ツール。

admin（API_KEY）か、GitHub ログインで発行した MCP トークンを持つ user だけが使える。
user には REST が本人所有リポジトリのみに絞り、`RestGateway` が応答を再検証する（fail closed）。
"""
from typing import Any

from mcp.server.fastmcp import Context, FastMCP

from app.mcp_server.gateway import RestGateway


def register(mcp: FastMCP) -> None:
    """非公開情報のツールを登録する（読み取り専用の GET のみ）。"""

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
        return await RestGateway(ctx).get("/api/depscan", {
            "repo": repo, "severity": severity, "ecosystem": ecosystem,
            "resolved": resolved, "page": page, "per_page": per_page,
        }, private=True)

    @mcp.tool()
    async def get_depscan_stats(ctx: Context) -> dict[str, Any]:
        """自分のリポジトリの、未解決の依存ライブラリ脆弱性の件数（リポジトリ別・重要度別）。"""
        return await RestGateway(ctx).get("/api/depscan/stats", private=True)

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
        return await RestGateway(ctx).get("/api/codescan", {
            "repo": repo, "severity": severity, "min_cvss": min_cvss,
            "resolved": resolved, "page": page, "per_page": per_page,
        }, private=True)

    @mcp.tool()
    async def get_codescan_stats(ctx: Context) -> dict[str, Any]:
        """自分のリポジトリの、未解決のコード脆弱性の件数（リポジトリ別・重要度別）。"""
        return await RestGateway(ctx).get("/api/codescan/stats", private=True)
