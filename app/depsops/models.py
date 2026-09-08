"""DEPSOPS（Dependabot PR 自動運用）ドメインの ORM モデル定義。
SQLAlchemy 2.x の Mapped + mapped_column スタイルを採用し、mypy との型互換性を確保する。
"""
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class DependabotPrLog(Base):
    """DEPSOPS の各実行で判定した Dependabot PR の履歴（自動マージ・要確認 双方）。

    実行のたびに `run_dependabot_ops` が判定した全 PR を1行ずつ記録する。
    Slack 通知は実行時点のスナップショットのみで履歴を持たないため、
    ダッシュボードで「要確認」PR の一覧・理由を後から確認できるようにする。
    """

    __tablename__ = "dependabot_pr_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # 対象リポジトリ（例: baby-feelings/baby_grow）
    repo_full_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Dependabot PR 番号
    pr_number: Mapped[int] = mapped_column(Integer, nullable=False)

    # PR タイトル
    title: Mapped[str] = mapped_column(Text, nullable=False)

    # "merged"（自動マージ済み）/ "flagged"（要確認・自動マージしなかった）
    action: Mapped[str] = mapped_column(String(20), nullable=False)

    # action="flagged" の場合の理由（メジャーバージョンアップ・CI未設定 等）。
    # action="merged" の場合は None
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    # このPRがセキュリティ更新（GitHub Dependabot alertの対象パッケージと一致）か、
    # 単なる定期バージョン更新かのヒューリスティック判定。
    # True=セキュリティ更新の可能性が高い / False=一致するalertなし（通常のバージョン更新）/
    # None=判定不能（GITHUB_TOKENにDependabot alerts: Read-only権限が無い等でalert取得に失敗）
    is_security_update: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    # 判定を行った DEPSOPS 実行日時
    processed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # DB 登録日時
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        # リポジトリ別フィルタリング高速化
        Index("ix_dependabot_pr_logs_repo", "repo_full_name"),
        # action（merged/flagged）でのフィルタリング高速化
        Index("ix_dependabot_pr_logs_action", "action"),
        # 実行日時降順の一覧表示高速化
        Index("ix_dependabot_pr_logs_processed_at", "processed_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<DependabotPrLog {self.repo_full_name}#{self.pr_number} "
            f"action={self.action}>"
        )
