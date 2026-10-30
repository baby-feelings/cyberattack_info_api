"""コミットの監視の状態の ORM モデル。"""
from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class CommitWatchState(Base):
    """リポジトリごとの、最後に確認した既定ブランチの先頭の SHA。

    ここから先のコミットだけを、次回に調べる。

    時刻ではなく SHA を基準にする（コミットの日時は、作者が偽れるため）。
    """

    __tablename__ = "commit_watch_states"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    repo_full_name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    last_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    # 最後に確認した日時（運用の参考。判定には使わない）
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
