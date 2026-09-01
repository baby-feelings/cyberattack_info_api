"""横断的（複数ドメインで共有される）Pydantic スキーマ定義。"""
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """ヘルスチェックエンドポイントのレスポンススキーマ。"""

    status: str
    environment: str
    db_connected: bool


class MonthlyStat(BaseModel):
    """月別集計（KEV / OSV / JVN 共通）。"""

    year_month: str = Field(description="YYYY-MM 形式")
    count: int


class SeverityStat(BaseModel):
    """重要度別件数（OSV / JVN / DEPSCAN 共通）。"""

    severity: str
    count: int
