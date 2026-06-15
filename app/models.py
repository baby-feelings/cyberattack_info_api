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


class CrawlerLog(Base):
    """クローラー実行履歴テーブル。
    KEV / OSV 各クローラーの実行結果（成功・失敗・件数・所要時間）を記録する。
    """

    __tablename__ = "crawler_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # クローラー種別（"KEV" / "OSV"）
    crawler_type: Mapped[str] = mapped_column(String(10), nullable=False)

    # 実行結果（"success" / "error"）
    status: Mapped[str] = mapped_column(String(10), nullable=False)

    # クローラー開始日時
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # クローラー終了日時（エラー中断時も記録）
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # 実行所要時間（秒）
    duration_seconds: Mapped[float] = mapped_column(Float, nullable=False)

    # 新規挿入件数
    inserted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # 更新件数
    updated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # 削除件数（OSV の保持期間超過削除分）
    deleted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # エラーメッセージ（status="error" のときのみ設定）
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        # 実行日時でのソート・フィルタリング高速化
        Index("ix_crawler_logs_started_at", "started_at"),
        # クローラー種別でのフィルタリング高速化
        Index("ix_crawler_logs_crawler_type", "crawler_type"),
    )

    def __repr__(self) -> str:
        return (
            f"<CrawlerLog {self.crawler_type} {self.status} "
            f"started={self.started_at.isoformat()}>"
        )


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
