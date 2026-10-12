"""公開情報（KEV / OSV / JVN）を参照する MCP ツール。認証済みの全主体が使える。"""
from typing import Any

from mcp.server.fastmcp import Context, FastMCP

from app.mcp_server.gateway import MAX_PER_PAGE, RestGateway


def register(mcp: FastMCP) -> None:
    """公開情報のツールを登録する（読み取り専用の GET のみ）。"""

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
        return await RestGateway(ctx).get("/api/vulnerabilities", {
            "search": search, "vendor": vendor, "product": product,
            "min_epss": min_epss, "page": page, "per_page": per_page,
        })

    @mcp.tool()
    async def get_recent_kev(ctx: Context, days: int = 30) -> dict[str, Any]:
        """直近 days 日（1〜365）に CISA KEV へ追加された脆弱性を、新しい順に返す。

        件数が多い期間でもコンテキストを圧迫しないよう、返すのは新しい順に最大 50 件。
        全体の件数は total で分かる（それ以上は search_kev でページを送って取得する）。
        """
        items = await RestGateway(ctx).get("/api/vulnerabilities/recent", {"days": days})
        return {"total": len(items), "data": items[:MAX_PER_PAGE]}

    @mcp.tool()
    async def get_kev(ctx: Context, cve_id: str) -> dict[str, Any]:
        """CVE ID（例: CVE-2024-3400）を指定して、KEV の脆弱性の詳細を1件取得する。"""
        return await RestGateway(ctx).get(f"/api/vulnerabilities/{cve_id}")

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
        return await RestGateway(ctx).get("/api/osv", {
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
        return await RestGateway(ctx).get("/api/jvn", {
            "search": search, "severity": severity, "days": days,
            "page": page, "per_page": per_page,
        })
