"""リポジトリの設定の監査結果の ORM モデル。"""
from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class RepoAudit(Base):
    """リポジトリ1件の、最新の監査結果（スコア・各項目の判定・前回からの変化）。"""

    __tablename__ = "repo_audits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    repo_full_name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    # 0〜100。点検できた項目の重み付きの達成率（取得不可・強制できない項目は、分母に含めない）
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # 各項目の判定 [{"key", "label", "status", "weight", "detail", "fix"}]
    checks: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    # デプロイキー・Webhook・共同編集者の名前の一覧（変化の検知用）
    snapshot: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    # 前回からの変化 [{"kind", "change", "name"}]（今回の監査で見つかったもの）
    changes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    audited_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False,
    )
