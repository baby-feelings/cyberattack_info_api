"""DEPSCAN（依存ライブラリ脆弱性スキャン）ドメインの ORM モデル定義。
SQLAlchemy 2.x の Mapped + mapped_column スタイルを採用し、mypy との型互換性を確保する。
"""
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
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


class DependencyFinding(Base):
    """依存ライブラリ脆弱性の検知結果テーブル（DEPSCAN 機能）。
    GitHub 上の自作アプリのロックファイルを OSV API とリアルタイム照合した結果を格納する。
    """

    __tablename__ = "dependency_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # 対象リポジトリ（例: baby-feelings/baby_grow）
    repo_full_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # エコシステム（例: PyPI / npm / Pub）
    ecosystem: Mapped[str] = mapped_column(String(50), nullable=False)

    # パッケージ名
    package_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # ロックファイルに記載されていたインストール済みバージョン
    installed_version: Mapped[str] = mapped_column(String(100), nullable=False)

    # OSV ID（例: GHSA-xxxx-xxxx-xxxx）
    osv_id: Mapped[str] = mapped_column(String(50), nullable=False)

    # 重要度ラベル（CRITICAL / HIGH / MEDIUM / LOW）
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # CVSS スコア
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # 脆弱性の概要
    summary: Mapped[str] = mapped_column(Text, nullable=False)

    # 修正済みバージョン一覧（JSON 配列）
    fixed_versions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # 検知元のロックファイルパス（例: dashboard/package-lock.json）
    manifest_path: Mapped[str] = mapped_column(String(500), nullable=False)

    # 到達可能性（import レベルのヒューリスティック判定）:
    # "reachable"（ソース内でimport/use確認）/ "unreachable"（該当拡張子のソースはあるが
    # importが見つからない）/ "unknown"（判定不能。該当拡張子のソースが無い・取得失敗等）
    reachability: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # リポジトリの公開範囲（GitHub APIの"private"フィールドから取得。Issue #131）:
    # "public"（一般公開コード）/ "private"（非公開）。スキャンのたびに上書きするため、
    # リポジトリの公開設定変更は次回スキャンで自動反映される
    repo_visibility: Mapped[str | None] = mapped_column(String(10), nullable=True)

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
        # (repo_full_name, ecosystem, package_name, osv_id) の複合ユニーク制約（Upsert の基準キー）
        UniqueConstraint(
            "repo_full_name", "ecosystem", "package_name", "osv_id",
            name="uq_dependency_findings",
        ),
        # リポジトリ別フィルタリング高速化
        Index("ix_dependency_findings_repo", "repo_full_name"),
        # 重要度フィルタリング高速化
        Index("ix_dependency_findings_severity", "severity"),
        # 未解決/解決済みフィルタリング高速化
        Index("ix_dependency_findings_resolved_at", "resolved_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<DependencyFinding {self.repo_full_name} "
            f"{self.package_name}@{self.installed_version} ({self.osv_id})>"
        )


class UserScan(Base):
    """GitHub ログイン経由でのオンデマンド DEPSCAN スキャンの実行状況。

    baby-feelings 以外の任意の GitHub アカウントがダッシュボードにログインした際、
    そのアカウント所有リポジトリを初回スキャンする処理の進捗をフロントエンドが
    ポーリングできるようにするための状態テーブル（1ユーザー1行）。
    """

    __tablename__ = "depscan_user_scans"

    # ログインした GitHub ユーザー名（login）
    username: Mapped[str] = mapped_column(String(255), primary_key=True)

    # "running" / "done" / "error"
    status: Mapped[str] = mapped_column(String(20), nullable=False)

    # スキャン対象リポジトリ数（完了後にセット）
    repos_scanned: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<UserScan {self.username} status={self.status}>"


class RepoAssetContext(Base):
    """リポジトリ単位の資産コンテキスト（Issue #131：多層リスク優先度づけ）。

    「その脆弱性が実際に自組織のどの資産に影響するか」を判断するための文脈情報
    （本番デプロイ済みか・インターネット公開サービスか・資産重要度）。GitHub API
    から自動取得できる repo_visibility（DependencyFinding側）とは異なり、これらは
    自動判定できないため、管理者が `PUT /admin/depscan/assets/{owner}/{repo}` で
    手動設定する。

    新しいリポジトリを作った時など変更頻度が低いため、POPULAR_PACKAGES等の静的な
    設定ファイルで管理する方式も検討したが、変更の都度デプロイが必要になるのを
    避けるため、他の管理系操作（DependabotPrLog等）と同様にDB+管理APIで管理する
    方式を採用した。
    """

    __tablename__ = "repo_asset_contexts"

    # 対象リポジトリ（例: baby-feelings/baby_grow）
    repo_full_name: Mapped[str] = mapped_column(String(255), primary_key=True)

    # 本番デプロイ済みか（未設定時はFalse扱い＝優先度に寄与しない安全側デフォルト）
    is_production: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # インターネットに公開されたサービスか
    is_internet_facing: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # 資産重要度（"high" / "medium" / "low"）。未設定（null）は「未評価」を意味し、
    # "low" とは区別する
    importance: Mapped[str | None] = mapped_column(String(20), nullable=True)

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

    def __repr__(self) -> str:
        return (
            f"<RepoAssetContext {self.repo_full_name} "
            f"production={self.is_production} importance={self.importance}>"
        )
