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
