"""Pydantic スキーマ定義。
APIリクエスト・レスポンスの型定義とバリデーションを担う。
"""
from datetime import date

from pydantic import BaseModel, Field


class VulnerabilityOut(BaseModel):
    """脆弱性情報の出力スキーマ（API レスポンス用）。"""

    cve_id: str = Field(description="CVE 番号 (例: CVE-2026-12345)")
    vendor_project: str = Field(description="ベンダー名 (例: Microsoft)")
    product: str = Field(description="製品名 (例: Windows)")
    vulnerability_name: str = Field(description="脆弱性の名称・タイトル")
    description: str = Field(description="脆弱性の詳細説明")
    required_action: str | None = Field(None, description="推奨される対策・アクション")
    date_added: date = Field(description="CISA KEV に追加された日")

    model_config = {"from_attributes": True}


class VulnerabilityListResponse(BaseModel):
    """一覧取得エンドポイントのレスポンススキーマ（ページネーション付き）。"""

    total: int = Field(description="総件数")
    page: int = Field(description="現在のページ番号")
    per_page: int = Field(description="1ページあたりの件数")
    data: list[VulnerabilityOut] = Field(description="脆弱性データ一覧")


class HealthResponse(BaseModel):
    """ヘルスチェックエンドポイントのレスポンススキーマ。"""

    status: str
    environment: str
    db_connected: bool


class CrawlResponse(BaseModel):
    """クローラー手動実行エンドポイントのレスポンススキーマ。"""

    message: str
    inserted: int
    updated: int


# ── 統計 ────────────────────────────────────────────────────────


class VendorStat(BaseModel):
    """ベンダー別集計。"""

    vendor_project: str
    count: int


class MonthlyStat(BaseModel):
    """月別集計。"""

    year_month: str = Field(description="YYYY-MM 形式")
    count: int


class StatsResponse(BaseModel):
    """統計エンドポイントのレスポンス。"""

    total_vulnerabilities: int = Field(description="総脆弱性件数")
    top_vendors: list[VendorStat] = Field(description="件数上位ベンダー（上位 10 件）")
    monthly_trend: list[MonthlyStat] = Field(description="月別追加件数（直近 12 ヶ月）")


# ── OSV 脆弱性 ───────────────────────────────────────────────────


class OsvVulnerabilityOut(BaseModel):
    """OSV 脆弱性情報の出力スキーマ。"""

    osv_id: str = Field(description="OSV ID（例: GHSA-xxxx / OSV-2024-xxxx）")
    ecosystem: str = Field(description="エコシステム（例: PyPI / npm）")
    package_name: str = Field(description="パッケージ名")
    aliases: list[str] = Field(description="エイリアス ID（CVE ID 等）")
    summary: str = Field(description="脆弱性の概要")
    details: str | None = Field(None, description="詳細説明")
    severity: str | None = Field(None, description="重要度（CRITICAL/HIGH/MEDIUM/LOW）")
    cvss_score: float | None = Field(None, description="CVSS スコア")
    affected_versions: list[str] = Field(description="影響を受けるバージョン（最大 30 件）")
    fixed_versions: list[str] = Field(description="修正済みバージョン")
    references: list[str] = Field(description="参考リンク（最大 5 件）")
    published: str = Field(description="公開日時（ISO 8601）")
    modified: str = Field(description="最終更新日時（ISO 8601）")

    model_config = {"from_attributes": True}

    @classmethod
    def model_validate(cls, obj, **kwargs):  # type: ignore[override]
        """datetime を ISO 文字列に変換して生成する。"""
        if hasattr(obj, "__dict__"):
            return cls(
                osv_id=obj.osv_id,
                ecosystem=obj.ecosystem,
                package_name=obj.package_name,
                aliases=obj.aliases or [],
                summary=obj.summary,
                details=obj.details,
                severity=obj.severity,
                cvss_score=obj.cvss_score,
                affected_versions=obj.affected_versions or [],
                fixed_versions=obj.fixed_versions or [],
                references=obj.references or [],
                published=obj.published.isoformat(),
                modified=obj.modified.isoformat(),
            )
        return super().model_validate(obj, **kwargs)


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


class OsvSeverityStat(BaseModel):
    """重要度別件数。"""

    severity: str
    count: int


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
