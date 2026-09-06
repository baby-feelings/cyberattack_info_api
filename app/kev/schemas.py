"""KEV（CISA Known Exploited Vulnerabilities）ドメインの Pydantic スキーマ定義。
APIリクエスト・レスポンスの型定義とバリデーションを担う。
"""
from datetime import date, datetime

from pydantic import BaseModel, Field

from app.core.schemas import MonthlyStat


class VulnerabilityOut(BaseModel):
    """脆弱性情報の出力スキーマ（API レスポンス用）。"""

    cve_id: str = Field(description="CVE 番号 (例: CVE-2026-12345)")
    vendor_project: str = Field(description="ベンダー名 (例: Microsoft)")
    product: str = Field(description="製品名 (例: Windows)")
    vulnerability_name: str = Field(description="脆弱性の名称・タイトル")
    description: str = Field(description="脆弱性の詳細説明")
    required_action: str | None = Field(None, description="推奨される対策・アクション")
    date_added: date = Field(description="CISA KEV に追加された日")
    epss_score: float | None = Field(
        None, description="EPSS スコア（今後30日以内に悪用される確率、0.0〜1.0）",
    )
    epss_percentile: float | None = Field(
        None, description="EPSS パーセンタイル（全 CVE 中での相対順位、0.0〜1.0）",
    )
    epss_updated_at: datetime | None = Field(
        None, description="EPSS スコアの取得日時",
    )

    model_config = {"from_attributes": True}


class VulnerabilityListResponse(BaseModel):
    """一覧取得エンドポイントのレスポンススキーマ（ページネーション付き）。"""

    total: int = Field(description="総件数")
    page: int = Field(description="現在のページ番号")
    per_page: int = Field(description="1ページあたりの件数")
    data: list[VulnerabilityOut] = Field(description="脆弱性データ一覧")


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


class StatsResponse(BaseModel):
    """統計エンドポイントのレスポンス。"""

    total_vulnerabilities: int = Field(description="総脆弱性件数")
    top_vendors: list[VendorStat] = Field(description="件数上位ベンダー（上位 10 件）")
    monthly_trend: list[MonthlyStat] = Field(description="月別追加件数（直近 12 ヶ月）")
