"""SQLAlchemy ORM モデル定義。
CISA KEV カタログの脆弱性データを格納する vulnerabilities テーブルを定義する。
SQLAlchemy 2.x の Mapped + mapped_column スタイルを採用し、mypy との型互換性を確保する。
"""
from datetime import date, datetime

from sqlalchemy import JSON, Date, DateTime, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Vulnerability(Base):
    """脆弱性情報テーブル（CISA KEV カタログに対応）。"""

    __tablename__ = "vulnerabilities"

    # 内部管理ID（自動採番）
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # CVE番号（例: CVE-2026-12345）—— ビジネスキーとして一意制約
    cve_id: Mapped[str] = mapped_column(String(30), nullable=False)

    # ベンダー・プロジェクト名（例: Microsoft, Apache）
    vendor_project: Mapped[str] = mapped_column(String(255), nullable=False)

    # 製品名（例: Windows, Log4j）
    product: Mapped[str] = mapped_column(String(255), nullable=False)

    # 脆弱性の名称・タイトル
    vulnerability_name: Mapped[str] = mapped_column(Text, nullable=False)

    # 脆弱性の詳細説明
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # 推奨される対策・アクション（任意）
    required_action: Mapped[str | None] = mapped_column(Text, nullable=True)

    # CISA KEV に追加された日
    date_added: Mapped[date] = mapped_column(Date, nullable=False)

    # DB 登録日時（自動セット）
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # DB 更新日時（更新時に自動セット）
    updated_at: Mapped[datetime] = mapped_column(
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


class ScanResult(Base):
    """スキャン結果の永続化テーブル。
    POST /api/scan および /api/scan/requirements の実行結果を保存する。
    """

    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # スキャン方法（packages / requirements / package-json）
    scan_type: Mapped[str] = mapped_column(String(30), nullable=False)

    # スキャン対象のパッケージ数
    scanned_packages: Mapped[int] = mapped_column(Integer, nullable=False)

    # 検出された脆弱性の総数
    total_findings: Mapped[int] = mapped_column(Integer, nullable=False)

    # 検出内容（JSON 配列）
    findings: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # スキャン実行日時
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        # スキャン日時インデックス（履歴一覧の高速取得用）
        Index("ix_scan_results_scanned_at", "scanned_at"),
    )
