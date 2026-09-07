"""横断的（複数ドメインで共有される）Pydantic スキーマ定義。"""
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class OrmDatetimeModel(BaseModel):
    """ORM オブジェクトの datetime 属性を自動で ISO 文字列に変換してから
    Pydantic の検証に委譲する基底クラス。

    素の `from_attributes=True` では、フィールド型を `str` と宣言した属性に
    ORM 側の datetime 値をそのまま渡すとバリデーションエラーになる。これを
    避けるため、JVN/OSV の出力スキーマは「ORM オブジェクトから手動で dict を
    構築し、日時だけ isoformat() してから super().model_validate() へ委譲する」
    実装を個別に持っていたが、フィールドを手動で列挙する方式は、新フィールド
    追加時に列挙し忘れるとサイレントにデフォルト値（None）へフォールバック
    してしまう（実際に fetched_at 追加時にこの事故が発生し、本番で常に null を
    返す不具合になった）。

    本クラスは列挙をやめ、Pydantic が認識している宣言済みフィールド一覧
    （`cls.model_fields`）を動的に読んで ORM オブジェクトから値を取り出し、
    datetime 型の属性だけ自動変換することで、この種のバグを構造的に防ぐ。
    """

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Any:
        if hasattr(obj, "__dict__") and not isinstance(obj, dict):
            data: dict[str, Any] = {}
            for name in cls.model_fields:
                value = getattr(obj, name, None)
                if isinstance(value, datetime):
                    value = value.isoformat()
                data[name] = value
            return super().model_validate(data, **kwargs)
        return super().model_validate(obj, **kwargs)


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
