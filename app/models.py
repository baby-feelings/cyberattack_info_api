"""SQLAlchemy ORM モデル定義。
CISA KEV カタログの脆弱性データを格納する vulnerabilities テーブルを定義する。
"""
from datetime import date, datetime

from sqlalchemy import Column, Date, DateTime, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.sql import func

from app.database import Base


class Vulnerability(Base):
    """脆弱性情報テーブル（CISA KEV カタログに対応）。"""

    __tablename__ = "vulnerabilities"

    # 内部管理ID（自動採番）
    id: int = Column(Integer, primary_key=True, autoincrement=True)

    # CVE番号（例: CVE-2026-12345）—— ビジネスキーとして一意制約
    cve_id: str = Column(String(30), nullable=False)

    # ベンダー・プロジェクト名（例: Microsoft, Apache）
    vendor_project: str = Column(String(255), nullable=False)

    # 製品名（例: Windows, Log4j）
    product: str = Column(String(255), nullable=False)

    # 脆弱性の名称・タイトル
    vulnerability_name: str = Column(Text, nullable=False)

    # 脆弱性の詳細説明
    description: str = Column(Text, nullable=False)

    # 推奨される対策・アクション（任意）
    required_action: str | None = Column(Text, nullable=True)

    # CISA KEV に追加された日
    date_added: date = Column(Date, nullable=False)

    # DB 登録日時（自動セット）
    created_at: datetime = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # DB 更新日時（更新時に自動セット）
    updated_at: datetime = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    __table_args__ = (
        # CVE ID のユニーク制約（Upsert の基準キー）
        UniqueConstraint("cve_id", name="uq_vulnerabilities_cve_id"),
        # ベンダー×製品の複合インデックス（フィルタリング高速化）
        Index("ix_vulnerabilities_vendor_product", "vendor_project", "product"),
        # 追加日インデックス（最新データ抽出の高速化）
        Index("ix_vulnerabilities_date_added", "date_added"),
    )

    def __repr__(self) -> str:
        return f"<Vulnerability {self.cve_id} ({self.vendor_project}/{self.product})>"
