"""CODESCAN（自アプリのコード自体の脆弱性診断）ドメインの ORM モデル定義。

DEPSCAN（依存ライブラリの脆弱性）と対をなす、Semgrep による静的解析ベースの
コード脆弱性検知結果を格納する。SQLAlchemy 2.x の Mapped + mapped_column
スタイルを採用し、mypy との型互換性を確保する（DEPSCAN と同じ方針）。
"""
from datetime import datetime

from sqlalchemy import (
    JSON,
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

from app.core.database import Base


class CodeFinding(Base):
    """自アプリのコード自体の脆弱性検知結果テーブル（CODESCAN 機能）。

    GitHub 上の自作アプリのソースコードを Semgrep（p/security-audit, p/secrets
    ルールセット）で静的解析した結果を格納する。DEPSCAN の `DependencyFinding`
    が「依存ライブラリの既知脆弱性」を扱うのに対し、こちらは「自アプリのコード
    自体に潜むパターン（SQLi・ハードコード認証情報・XSS等）」を扱う。
    """

    __tablename__ = "code_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # 対象リポジトリ（例: baby-feelings/baby_grow）
    repo_full_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # リポジトリルートからの相対パス
    file_path: Mapped[str] = mapped_column(String(1000), nullable=False)

    # 該当コードの開始行・終了行
    line_start: Mapped[int] = mapped_column(Integer, nullable=False)
    line_end: Mapped[int] = mapped_column(Integer, nullable=False)

    # Semgrep のルールID（例: python.lang.security.audit.hardcoded-password）。
    # gitleaks 由来のレコードは Semgrep とのルールID衝突を避けるため
    # "gitleaks:<RuleID>" のプレフィックスを付与する（app.codescan.crawler._parse_gitleaks_results）
    rule_id: Mapped[str] = mapped_column(String(500), nullable=False)

    # 検知内容の説明（Semgrepの extra.message）
    message: Mapped[str] = mapped_column(Text, nullable=False)

    # Semgrep の重要度（"ERROR" / "WARNING" / "INFO"）
    severity: Mapped[str] = mapped_column(String(20), nullable=False)

    # CWE ID一覧（extra.metadata.cwe から抽出。無ければ空配列）
    cwe_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # OWASP カテゴリ一覧（extra.metadata.owasp から抽出。無ければ空配列）
    owasp_categories: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # 該当コード抜粋（extra.lines。長すぎる場合は切り詰め済み）
    code_snippet: Mapped[str] = mapped_column(Text, nullable=False)

    # CVSS 3.1 基本値（app.codescan.cvss_mapping によるベストエフォート推定。
    # 未算出・算出失敗時は null）
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # CVSS 3.1 ベクター文字列（同上、ベストエフォート）
    cvss_vector: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # 検知したツール（"semgrep" / "gitleaks"）。既存レコードとの後方互換のため
    # server_default で "semgrep" を設定する（gitleaks 導入以前のレコードは全て
    # Semgrep 由来のため）
    tool: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="semgrep",
    )

    # 初回検知日時
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # 解決日時（直近スキャンで検知されなくなった場合にセット。未解決なら None）
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

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
        # (repo_full_name, file_path, rule_id, line_start) の複合ユニーク制約
        # （Upsert の基準キー。Semgrepには安定した検知ID的なものが無いため、この
        # 4値の組み合わせで同一問題とみなす。DEPSCANの4値ユニークキーと同じ考え方）
        UniqueConstraint(
            "repo_full_name", "file_path", "rule_id", "line_start",
            name="uq_code_findings",
        ),
        # リポジトリ別フィルタリング高速化
        Index("ix_code_findings_repo", "repo_full_name"),
        # 重要度フィルタリング高速化
        Index("ix_code_findings_severity", "severity"),
        # 未解決/解決済みフィルタリング高速化
        Index("ix_code_findings_resolved_at", "resolved_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<CodeFinding {self.repo_full_name} {self.file_path}:{self.line_start} "
            f"({self.rule_id})>"
        )
