"""DB ユーティリティ関数。

複数ルーターで共通して使用するヘルパーを提供する。
"""
from sqlalchemy import func
from sqlalchemy.sql.elements import ColumnElement

from app.database import engine


def year_month_expr(column) -> ColumnElement[str]:  # type: ignore[type-arg]
    """SQLite / PostgreSQL 両対応の YYYY-MM フォーマット式を返す。"""
    if "sqlite" in engine.dialect.name:
        return func.strftime("%Y-%m", column)  # type: ignore[return-value]
    return func.to_char(column, "YYYY-MM")  # type: ignore[return-value]
