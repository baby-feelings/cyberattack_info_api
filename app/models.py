"""SQLAlchemy ORM モデル定義。
CISA KEV カタログおよび OSV (Open Source Vulnerabilities) の脆弱性データを格納する。
SQLAlchemy 2.x の Mapped + mapped_column スタイルを採用し、mypy との型互換性を確保する。
"""
from datetime import date, datetime

from sqlalchemy import (
    JSON,
    Date,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
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


class OsvVulnerability(Base):
    """OSV 脆弱性情報テーブル（Open Source Vulnerabilities に対応）。
    1つの OSV エントリが複数パッケージに影響する場合は複数行として格納する。
    """

    __tablename__ = "osv_vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # OSV ID（例: GHSA-xxxx-xxxx-xxxx / OSV-2024-xxxx）
    osv_id: Mapped[str] = mapped_column(String(50), nullable=False)

    # エコシステム（例: PyPI / npm / Go）
    ecosystem: Mapped[str] = mapped_column(String(50), nullable=False)

    # パッケージ名（例: fastapi / express）
    package_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # エイリアス ID 一覧（CVE ID など）
    aliases: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # 脆弱性の概要
    summary: Mapped[str] = mapped_column(Text, nullable=False)

    # 詳細説明（任意）
    details: Mapped[str | None] = mapped_column(Text, nullable=True)

    # 重要度ラベル（CRITICAL / HIGH / MEDIUM / LOW）
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # CVSS スコア（例: 9.8）
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # 影響を受けるバージョン一覧（JSON 配列、最大 30 件）
    affected_versions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # 修正済みバージョン一覧（JSON 配列）
    fixed_versions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # 参考リンク（JSON 配列、最大 5 件）
    references: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # OSV 公開日時
    published: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # OSV 最終更新日時（クローラーの取得対象日時フィルタのキー）
    modified: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

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
        # (osv_id, ecosystem, package_name) の複合ユニーク制約（Upsert の基準キー）
        UniqueConstraint(
            "osv_id", "ecosystem", "package_name",
            name="uq_osv_vulnerabilities",
        ),
        # エコシステムフィルタリング高速化
        Index("ix_osv_vulnerabilities_ecosystem", "ecosystem"),
        # 重要度フィルタリング高速化
        Index("ix_osv_vulnerabilities_severity", "severity"),
        # 更新日時でのソート・フィルタリング高速化
        Index("ix_osv_vulnerabilities_modified", "modified"),
    )

    def __repr__(self) -> str:
        return f"<OsvVulnerability {self.osv_id} ({self.ecosystem}/{self.package_name})>"
