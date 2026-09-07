"""OSV（Open Source Vulnerabilities）ドメインの Pydantic スキーマ定義。"""
from pydantic import BaseModel, Field

from app.core.schemas import MonthlyStat, OrmDatetimeModel, SeverityStat


class OsvVulnerabilityOut(OrmDatetimeModel):
    """OSV 脆弱性情報の出力スキーマ。

    datetime → ISO 文字列変換は OrmDatetimeModel（app.core.schemas）が
    フィールド列挙なしで自動的に行う。
    """

    osv_id: str = Field(description="OSV ID（例: GHSA-xxxx / OSV-2024-xxxx）")
    ecosystem: str = Field(description="エコシステム（例: PyPI / npm）")
    package_name: str = Field(description="パッケージ名")
    aliases: list[str] = Field(default_factory=list, description="エイリアス ID（CVE ID 等）")
    summary: str = Field(description="脆弱性の概要")
    details: str | None = Field(None, description="詳細説明")
    severity: str | None = Field(None, description="重要度（CRITICAL/HIGH/MEDIUM/LOW）")
    cvss_score: float | None = Field(None, description="CVSS スコア")
    affected_versions: list[str] = Field(
        default_factory=list, description="影響を受けるバージョン（最大 30 件）"
    )
    fixed_versions: list[str] = Field(default_factory=list, description="修正済みバージョン")
    references: list[str] = Field(default_factory=list, description="参考リンク（最大 5 件）")
    published: str = Field(description="公開日時（ISO 8601）")
    modified: str = Field(description="最終更新日時（ISO 8601）")
    withdrawn_at: str | None = Field(
        None, description="撤回日時（ISO 8601）。設定されていればソース側で撤回済み",
    )
    fetched_at: str | None = Field(
        None, description="このレコードを最後にOSV APIで存在確認した日時",
    )

    model_config = {"from_attributes": True}


class OsvListResponse(BaseModel):
    """OSV 一覧取得レスポンス（ページネーション付き）。"""

    total: int = Field(description="総件数")
    page: int = Field(description="現在のページ番号")
    per_page: int = Field(description="1ページあたりの件数")
    data: list[OsvVulnerabilityOut] = Field(description="OSV 脆弱性一覧")


class OsvEcosystemStat(BaseModel):
    """エコシステム別件数。"""

    ecosystem: str
    count: int


# 後方互換エイリアス
OsvSeverityStat = SeverityStat


class OsvStatsResponse(BaseModel):
    """OSV 統計エンドポイントのレスポンス。"""

    total: int = Field(description="総件数")
    ecosystems: list[OsvEcosystemStat] = Field(description="エコシステム別件数")
    severities: list[OsvSeverityStat] = Field(description="重要度別件数")
    monthly_trend: list[MonthlyStat] = Field(description="月別件数（直近 12 ヶ月）")


class OsvCrawlResponse(BaseModel):
    """OSV クローラー手動実行レスポンス。"""

    message: str
    inserted: int
    updated: int
    deleted: int = 0
