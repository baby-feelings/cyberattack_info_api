"""GitHub のセキュリティアラートの ORM モデル。"""
from datetime import datetime

from sqlalchemy import JSON, DateTime, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# アラートの種類
KIND_SECRET = "secret"  # noqa: S105 - 種類の名前（secret scanning）で、認証情報ではない
# ↑ secret scanning（履歴に残ったシークレット・有効性）
KIND_DEPENDABOT = "dependabot"  # Dependabot alerts（依存ライブラリの脆弱性）
KIND_CODE = "code"              # code scanning（CodeQL 等）
KINDS = (KIND_SECRET, KIND_DEPENDABOT, KIND_CODE)

# 取得の状態
SOURCE_AVAILABLE = "available"      # 取得できた
SOURCE_UNAVAILABLE = "unavailable"  # 取得できない（機能が無効・権限不足）


class GithubAlert(Base):
    """GitHub が持つアラート1件（リポジトリ・種類・番号で一意）。

    【重要・セキュリティ】secret scanning のアラートには、シークレットの値そのものが含まれるが、
    **保存しない**（種類・有効性・場所だけを持つ）。
    """

    __tablename__ = "github_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    repo_full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    number: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    html_url: Mapped[str] = mapped_column(String(500), nullable=False)
    # 種類ごとの補足（secret: secret_type・validity / dependabot: ecosystem・package・ghsa_id・
    # fixed_version / code: path・tool）
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False,
    )

    __table_args__ = (
        UniqueConstraint("kind", "repo_full_name", "number", name="uq_github_alerts"),
        Index("ix_github_alerts_repo", "repo_full_name"),
    )


class GithubAlertSource(Base):
    """リポジトリ×種類ごとの、取得の状態（取得できない項目を「取得不可」と示すため）。"""

    __tablename__ = "github_alert_sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    repo_full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    # 取得できない理由（例: 「機能が無効、または権限がありません（HTTP 404）」）
    reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("kind", "repo_full_name", name="uq_github_alert_sources"),
    )
