"""検知の例外（受容など）の ORM モデル。

検知テーブル（`dependency_findings`・`code_findings`）は、スキャンのたびに更新・解決済み化・
削除される。例外を検知の行に持たせると消えてしまうため、別のテーブルに、検知の同一性キー
（`finding_key`）で結び付けて持つ（検知が解決して再発しても、例外が引き継がれる）。
"""
from datetime import datetime

from sqlalchemy import DateTime, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base

# 検知の種別（どの検知テーブルの例外か）
KIND_DEPENDENCY = "dependency"
KIND_CODE = "code"
KINDS = (KIND_DEPENDENCY, KIND_CODE)

# 例外の状態。「対応中」は例外を持たない状態（行が無い・解除済み）で表す
STATUS_ACCEPTED = "accepted"            # 受容（修正できない・しない。期限つき）
STATUS_FALSE_POSITIVE = "false_positive"  # 誤検知
STATUS_NOT_AFFECTED = "not_affected"    # 影響なし（到達できない等）
STATUSES = (STATUS_ACCEPTED, STATUS_FALSE_POSITIVE, STATUS_NOT_AFFECTED)

# 例外が終わった理由
ENDED_EXPIRED = "expired"              # 期限切れ
ENDED_FIX_AVAILABLE = "fix_available"  # 修正版の公開
ENDED_REVOKED = "revoked"              # 手動で解除


class FindingException(Base):
    """検知の例外（理由・期限・承認者つき）。"""

    __tablename__ = "finding_exceptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # "dependency"（DEPSCAN）/ "code"（CODESCAN）
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    repo_full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    # 検知の同一性キー。dependency="ecosystem|package|osv_id"・code="file_path|rule_id"
    # （コードは行番号を含めない。行がずれても、例外が外れないようにする）
    finding_key: Mapped[str] = mapped_column(String(1000), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    # 例外の期限（受容は必須。誤検知・影響なしは省略可）
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approver: Mapped[str] = mapped_column(String(100), nullable=False)
    # 終了（解除・期限切れ・修正版の公開）した日時と理由。NULL の間は有効
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_reason: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # 「期限の7日前」の通知を送った日時（二重に送らないため）
    expiry_notified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False,
    )

    __table_args__ = (
        Index("ix_finding_exceptions_target", "kind", "repo_full_name"),
        Index("ix_finding_exceptions_ended_at", "ended_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<FindingException {self.kind} {self.repo_full_name} "
            f"{self.finding_key} {self.status}>"
        )
