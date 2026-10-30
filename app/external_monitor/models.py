"""公開サイトの外形監視の結果の ORM モデル。"""
from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class SiteCheck(Base):
    """公開サイト1件の、最新の点検結果。"""

    __tablename__ = "site_checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    url: Mapped[str] = mapped_column(String(500), nullable=False, unique=True)
    # 由来（repo の Homepage・Firebase・GitHub Pages・設定）と、紐づくリポジトリ（無ければ空）
    source: Mapped[str] = mapped_column(String(30), nullable=False)
    repo_full_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # TLS 証明書の残り日数（取得できなければ NULL。無効・期限切れは負または findings に記録）
    tls_days_left: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # 見つかった問題 [{"rule", "severity", "message"}]
    findings: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False,
    )
