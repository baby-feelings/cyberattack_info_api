"""監査ログの ORM モデル。"""
from datetime import datetime

from sqlalchemy import DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AuditLog(Base):
    """監査ログ1件（誰が・いつ・何を・結果）。"""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # api-key / session / anonymous（ミドルウェアが判定）、または、ユーザー名（明示の記録）
    actor: Mapped[str] = mapped_column(String(100), nullable=False)
    # 例: "POST /admin/depscan-crawl"・"mcp_token_issued"
    action: Mapped[str] = mapped_column(String(200), nullable=False)
    # ok（成功）/ denied（認証・認可の失敗）/ throttled（レート制限）/ error
    outcome: Mapped[str] = mapped_column(String(20), nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)

    __table_args__ = (Index("ix_audit_logs_occurred_at", "occurred_at"),)
