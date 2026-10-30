"""セキュリティ態勢を参照する MCP ツール（Issue #422）。

言語・実行環境のバージョン、対応状況（SLA）、検知の例外（VEX）、GitHub のセキュリティアラート、
リポジトリ設定の監査、公開サイトの外形監視。いずれも、本人所有のリポジトリのみ（REST が絞り、
`RestGateway` が応答を再検証する）。admin（API_KEY）か、GitHub ログインで発行した
MCP トークンが必要。
読み取り専用の GET のみ（登録・解除・手動実行は、ツール化しない）。
"""
from typing import Any, Literal

from mcp.server.fastmcp import Context, FastMCP

from app.mcp_server.gateway import RestGateway


def register(mcp: FastMCP) -> None:
    """セキュリティ態勢のツールを登録する（読み取り専用の GET のみ）。"""

    @mcp.tool()
    async def list_runtimes(
        ctx: Context,
        repo: str | None = None,
        runtime: str | None = None,
        needs_action: bool = False,
        page: int = 1,
        per_page: int = 20,
    ) -> dict[str, Any]:
        """自分のリポジトリが使っている言語・実行環境（Python・Node.js・Flutter・Dart）の版と、状態を返す。

        状態は、サポート終了（eol）・期限間近（eol_soon）・新しい系列あり（update_available）など。
        needs_action=True で、対応が必要なものだけ。repo は "owner/repo"。MCP トークンが必要。
        """
        return await RestGateway(ctx).get("/api/runtimes", {
            "repo": repo, "runtime": runtime, "needs_action": needs_action,
            "page": page, "per_page": per_page,
        }, private=True)

    @mcp.tool()
    async def get_sla_report(
        ctx: Context, repo: str | None = None, window_days: int | None = None,
    ) -> dict[str, Any]:
        """脆弱性への対応状況: 重要度ごとの対応期限（SLA）を超えている検知と、平均対応日数（MTTR）。

        期限は CRITICAL 7日・HIGH 30日・MEDIUM 90日（KEV 掲載済みは 7日）。
        受容などの例外にした検知は、期限の計算から外れる。
        window_days は MTTR を集計する、解決済みの期間（日）。MCP トークンが必要。
        """
        return await RestGateway(ctx).get(
            "/api/sla", {"repo": repo, "window_days": window_days}, private=True,
        )

    @mcp.tool()
    async def list_finding_exceptions(
        ctx: Context,
        kind: Literal["dependency", "code"] | None = None,
        repo: str | None = None,
        include_ended: bool = False,
    ) -> dict[str, Any]:
        """検知の例外（受容・誤検知・影響なし）の一覧。理由・期限・承認者つき。

        例外にした検知は、通知・「要対応」の件数・対応期限から外れている。include_ended=True で、
        終了（解除・期限切れ・修正版の公開）したものも。登録・解除は、ツール化していない。
        MCP トークンが必要。
        """
        return await RestGateway(ctx).get("/api/exceptions", {
            "kind": kind, "repo": repo, "include_ended": include_ended,
        }, private=True)

    @mcp.tool()
    async def export_vex(
        ctx: Context, repo: str, format: Literal["openvex", "cyclonedx"] = "openvex",
    ) -> dict[str, Any]:
        """自分のリポジトリの、有効な例外（依存ライブラリ）を、VEX（OpenVEX・CycloneDX）で出力する。

        受容は affected（対応を記載）、誤検知・影響なしは not_affected。
        repo は "owner/repo"（必須）。MCP トークンが必要。
        """
        return await RestGateway(ctx).get(
            "/api/exceptions/vex", {"repo": repo, "format": format}, private=True,
        )

    @mcp.tool()
    async def list_github_alerts(
        ctx: Context,
        kind: Literal["secret", "dependabot", "code"] | None = None,
        repo: str | None = None,
        resolved: bool = False,
    ) -> dict[str, Any]:
        """GitHub のセキュリティアラート（secret scanning・Dependabot alerts・code scanning）。

        secret は、履歴に残ったシークレットと有効性（値そのものは含まれない）。取得できない項目
        （機能が無効・権限不足）は unavailable に示す。resolved=True で、解決済みも。
        MCP トークンが必要。
        """
        return await RestGateway(ctx).get("/api/github-alerts", {
            "kind": kind, "repo": repo, "resolved": resolved,
        }, private=True)

    @mcp.tool()
    async def compare_dependabot_and_depscan(ctx: Context) -> dict[str, Any]:
        """Dependabot alerts と DEPSCAN の検知を突き合わせる（both・only_github・only_depscan）。

        片方だけが検知したものは、検知の抜けか、データ源の違いの手がかり。MCP トークンが必要。
        """
        return await RestGateway(ctx).get("/api/github-alerts/compare", private=True)

    @mcp.tool()
    async def get_repo_audit(ctx: Context, only_issues: bool = False) -> dict[str, Any]:
        """リポジトリのセキュリティ設定の監査結果（スコア 0〜100・各項目の判定・前回からの変化）。

        secret scanning・push protection・Dependabot・ブランチ保護・フォーク・
        デプロイキー・Webhook。
        取得できない項目は unavailable、非公開の無料リポジトリのブランチ保護は not_enforceable で、
        不備（ng）と区別される。only_issues=True で、改善すべき項目があるリポジトリだけ。
        MCP トークンが必要。
        """
        return await RestGateway(ctx).get(
            "/api/repo-audit", {"only_issues": only_issues}, private=True,
        )

    @mcp.tool()
    async def get_site_monitor(ctx: Context, only_issues: bool = False) -> dict[str, Any]:
        """公開サイトの外形監視の結果。

        TLS 証明書の残り日数・ヘッダー・露出ファイル・DNS・Firestore。

        問題の重いサイトが先。only_issues=True で、問題（ERROR・WARNING）があるサイトだけ。
        自分のリポジトリに紐づくサイトのみ。MCP トークンが必要。
        """
        return await RestGateway(ctx).get(
            "/api/site-monitor", {"only_issues": only_issues}, private=True,
        )
