"""コミットの監視の状態の ORM モデル。"""
from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class CommitWatchState(Base):
    """リポジトリごとの、最後に確認した時刻（これ以降のコミットだけを調べる）。"""

    __tablename__ = "commit_watch_states"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    repo_full_name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
