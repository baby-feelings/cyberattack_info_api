"""クローラー実行ログドメインの Pydantic スキーマ定義。"""
from pydantic import BaseModel, Field


class CrawlerLogOut(BaseModel):
    """クローラー実行ログの出力スキーマ。"""

    id: int = Field(description="ログ ID")
    crawler_type: str = Field(description="クローラー種別（KEV / OSV / JVN / DEPSCAN）")
    status: str = Field(description="実行結果（success / error）")
    started_at: str = Field(description="開始日時（ISO 8601）")
    finished_at: str = Field(description="終了日時（ISO 8601）")
    duration_seconds: float = Field(description="所要時間（秒）")
    inserted: int = Field(description="新規挿入件数")
    updated: int = Field(description="更新件数")
    deleted: int = Field(description="削除件数（OSV のみ）")
    error_message: str | None = Field(None, description="エラーメッセージ")

    model_config = {"from_attributes": True}
