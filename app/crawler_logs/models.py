"""クローラー実行ログドメインの ORM モデル定義。
SQLAlchemy 2.x の Mapped + mapped_column スタイルを採用し、mypy との型互換性を確保する。
"""
from datetime import datetime

from sqlalchemy import DateTime, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class CrawlerLog(Base):
    """クローラー実行履歴テーブル。
    KEV / OSV / JVN / DEPSCAN 各クローラーの実行結果（成功・失敗・件数・所要時間）を記録する。
    """

    __tablename__ = "crawler_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # クローラー種別（"KEV" / "OSV" / "JVN" / "DEPSCAN"）
    crawler_type: Mapped[str] = mapped_column(String(10), nullable=False)

    # 実行結果（"success" / "error"）
    status: Mapped[str] = mapped_column(String(10), nullable=False)

    # クローラー開始日時
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # クローラー終了日時（エラー中断時も記録）
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # 実行所要時間（秒）
    duration_seconds: Mapped[float] = mapped_column(Float, nullable=False)

    # 新規挿入件数
    inserted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # 更新件数
    updated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # 削除件数（OSV の保持期間超過削除分）
    deleted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # エラーメッセージ（status="error" のときのみ設定）
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        # 実行日時でのソート・フィルタリング高速化
        Index("ix_crawler_logs_started_at", "started_at"),
        # クローラー種別でのフィルタリング高速化
        Index("ix_crawler_logs_crawler_type", "crawler_type"),
    )

    def __repr__(self) -> str:
        return (
            f"<CrawlerLog {self.crawler_type} {self.status} "
            f"started={self.started_at.isoformat()}>"
        )
