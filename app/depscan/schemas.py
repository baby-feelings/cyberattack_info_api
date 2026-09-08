"""DEPSCAN（依存ライブラリ脆弱性スキャン）ドメインの Pydantic スキーマ定義。"""
from pydantic import BaseModel, Field

from app.core.schemas import OrmDatetimeModel, SeverityStat


class DependencyFindingOut(OrmDatetimeModel):
    """依存ライブラリ脆弱性の検知結果の出力スキーマ。

    datetime → ISO 文字列変換は OrmDatetimeModel（app.core.schemas）が
    フィールド列挙なしで自動的に行う。
    """

    repo_full_name: str = Field(description="対象リポジトリ（例: baby-feelings/baby_grow）")
    ecosystem: str = Field(description="エコシステム（例: PyPI / npm / Pub）")
    package_name: str = Field(description="パッケージ名")
    installed_version: str = Field(description="インストール済みバージョン")
    osv_id: str = Field(description="OSV ID（例: GHSA-xxxx-xxxx-xxxx）")
    severity: str | None = Field(None, description="重要度（CRITICAL/HIGH/MEDIUM/LOW）")
    cvss_score: float | None = Field(None, description="CVSS スコア")
    summary: str = Field(description="脆弱性の概要")
    fixed_versions: list[str] = Field(default_factory=list, description="修正済みバージョン")
    manifest_path: str = Field(description="検知元のロックファイルパス")
    reachability: str | None = Field(
        None,
        description="到達可能性（import レベルのヒューリスティック判定）: "
        "reachable（importを確認） / unreachable（該当拡張子のソースはあるがimportなし） / "
        "unknown（判定不能）",
    )
    detected_at: str = Field(description="初回検知日時（ISO 8601）")
    resolved_at: str | None = Field(None, description="解決日時（未解決なら null）")

    model_config = {"from_attributes": True}


class DependencyFindingListResponse(BaseModel):
    """DEPSCAN 一覧取得レスポンス（ページネーション付き）。"""

    total: int = Field(description="総件数")
    page: int = Field(description="現在のページ番号")
    per_page: int = Field(description="1ページあたりの件数")
    data: list[DependencyFindingOut] = Field(description="依存ライブラリ脆弱性一覧")


class RepoStat(BaseModel):
    """リポジトリ別件数（DEPSCAN）。"""

    repo_full_name: str
    count: int


class DependencyFindingStatsResponse(BaseModel):
    """DEPSCAN 統計エンドポイントのレスポンス。"""

    total: int = Field(description="未解決の総件数")
    repos: list[RepoStat] = Field(description="リポジトリ別件数")
    severities: list[SeverityStat] = Field(description="重要度別件数")


class DepscanCrawlResponse(BaseModel):
    """DEPSCAN 手動実行レスポンス。"""

    message: str
    new_findings: int
    resolved: int
    repos_scanned: int
