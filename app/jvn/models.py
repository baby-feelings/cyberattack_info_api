"""JVN（Japan Vulnerability Notes）ドメインの ORM モデル定義。
SQLAlchemy 2.x の Mapped + mapped_column スタイルを採用し、mypy との型互換性を確保する。
"""
from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class JvnVulnerability(Base):
    """JVN 脆弱性情報テーブル（MyJVN API / JVNDB に対応）。"""

    __tablename__ = "jvn_vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # JVNDB ID（例: JVNDB-2026-020171）—— ビジネスキーとして一意制約
    jvndb_id: Mapped[str] = mapped_column(String(50), nullable=False)

    # 脆弱性タイトル
    title: Mapped[str] = mapped_column(Text, nullable=False)

    # 概要説明（HTML タグ除去済み）
    overview: Mapped[str] = mapped_column(Text, nullable=False)

    # 関連 CVE ID 一覧（例: ["CVE-2026-12345"]）
    cve_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # 重要度ラベル（High / Medium / Low）
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # CVSS スコア（例: 9.8）
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # CVSS ベクター文字列（例: AV:N/AC:L/Au:N/C:C/I:C/A:C）
    cvss_vector: Mapped[str | None] = mapped_column(String(200), nullable=True)

    # 影響を受ける製品一覧（JSON 配列: [{vendor, product, cpe}]）
    affected_products: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # 参考リンク一覧（JSON 配列: [{source, id, title, url}]）
    references: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # JVNDB エントリの URL
    jvn_url: Mapped[str] = mapped_column(String(500), nullable=False)

    # 公開日時
    date_published: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # 最終更新日時（クローラーのフィルタキー）
    date_last_modified: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # DB 登録日時
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # DB 更新日時
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    __table_args__ = (
        # JVNDB ID のユニーク制約（Upsert の基準キー）
        UniqueConstraint("jvndb_id", name="uq_jvn_vulnerabilities_jvndb_id"),
        # 重要度フィルタリング高速化
        Index("ix_jvn_vulnerabilities_severity", "severity"),
        # 更新日時でのソート・フィルタリング高速化
        Index("ix_jvn_vulnerabilities_date_last_modified", "date_last_modified"),
    )

    def __repr__(self) -> str:
        return f"<JvnVulnerability {self.jvndb_id}>"
