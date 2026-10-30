"""DB ユーティリティ関数。

複数ルーターで共通して使用するヘルパーを提供する。
"""
from datetime import UTC, datetime

from sqlalchemy import func
from sqlalchemy.sql.elements import ColumnElement

from app.core.database import engine


def year_month_expr(column) -> ColumnElement[str]:  # type: ignore[type-arg]
    """SQLite / PostgreSQL 両対応の YYYY-MM フォーマット式を返す。"""
    if "sqlite" in engine.dialect.name:
        return func.strftime("%Y-%m", column)  # type: ignore[return-value]
    return func.to_char(column, "YYYY-MM")  # type: ignore[return-value]


def as_utc(value: datetime) -> datetime:
    """タイムゾーンの無い日時（SQLite は tz を保持しない）は UTC として扱い、aware にそろえる。"""
    return value if value.tzinfo else value.replace(tzinfo=UTC)
