"""JVN（Japan Vulnerability Notes）ドメインの Pydantic スキーマ定義。"""
from typing import Any

from pydantic import BaseModel, Field, field_serializer

from app.core.schemas import MonthlyStat, SeverityStat


class JvnVulnerabilityOut(BaseModel):
    """JVN 脆弱性情報の出力スキーマ。"""

    jvndb_id: str = Field(description="JVNDB ID（例: JVNDB-2026-020171）")
    title: str = Field(description="脆弱性タイトル")
    overview: str = Field(description="概要説明")
    cve_ids: list[str] = Field(description="関連 CVE ID 一覧")
    severity: str | None = Field(None, description="重要度（High / Medium / Low）")
    cvss_score: float | None = Field(None, description="CVSS スコア")
    cvss_vector: str | None = Field(None, description="CVSS ベクター文字列")
    affected_products: list[dict[str, str]] = Field(
        default_factory=list, description="影響製品一覧"
    )
    references: list[dict[str, str]] = Field(default_factory=list, description="参考リンク一覧")
    jvn_url: str = Field(description="JVNDB エントリの URL")
    date_published: str = Field(description="公開日時（ISO 8601）")
    date_last_modified: str = Field(description="最終更新日時（ISO 8601）")

    model_config = {"from_attributes": True}

    @field_serializer("date_published", "date_last_modified")
    def _serialize_datetime(self, value: Any) -> str:
        """datetime を ISO 文字列に変換する。"""
        return value.isoformat() if hasattr(value, "isoformat") else str(value)

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> "JvnVulnerabilityOut":
        """ORM オブジェクトを dict に変換し、Pydantic 検証経路へ委譲する。"""
        if hasattr(obj, "__dict__"):
            data = {
                "jvndb_id": obj.jvndb_id,
                "title": obj.title,
                "overview": obj.overview,
                "cve_ids": obj.cve_ids or [],
                "severity": obj.severity,
                "cvss_score": obj.cvss_score,
                "cvss_vector": obj.cvss_vector,
                "affected_products": obj.affected_products or [],
                "references": obj.references or [],
                "jvn_url": obj.jvn_url,
                "date_published": obj.date_published.isoformat(),
                "date_last_modified": obj.date_last_modified.isoformat(),
            }
            return super().model_validate(data, **kwargs)
        return super().model_validate(obj, **kwargs)


class JvnListResponse(BaseModel):
    """JVN 一覧取得レスポンス（ページネーション付き）。"""

    total: int = Field(description="総件数")
    page: int = Field(description="現在のページ番号")
    per_page: int = Field(description="1ページあたりの件数")
    data: list[JvnVulnerabilityOut] = Field(description="JVN 脆弱性一覧")


# JvnSeverityStat は SeverityStat と同一のため統合
JvnSeverityStat = SeverityStat


class JvnStatsResponse(BaseModel):
    """JVN 統計エンドポイントのレスポンス。"""

    total: int = Field(description="総件数")
    severities: list[JvnSeverityStat] = Field(description="重要度別件数")
    monthly_trend: list[MonthlyStat] = Field(description="月別件数（直近 12 ヶ月）")


class JvnCrawlResponse(BaseModel):
    """JVN クローラー手動実行レスポンス。"""

    message: str
    inserted: int
    updated: int
