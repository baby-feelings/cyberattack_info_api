"""言語・実行環境のバージョン監視（RUNTIME）の ORM モデル。"""
from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, Index, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class RuntimeRelease(Base):
    """言語・実行環境のリリース（バージョン系列ごとの最新版とサポート期限）。

    取得元（endoflife.date・Flutter 公式のリリース情報）の内容を、毎日のクロールで上書きする。
    「系列（cycle）」は、Python・Flutter・Dart では `3.13` のようなメジャー.マイナー、
    Node.js では `24` のようなメジャーのこと。
    """

    __tablename__ = "runtime_releases"
    __table_args__ = (UniqueConstraint("runtime", "cycle", name="uq_runtime_releases"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # 言語・実行環境（python / nodejs / flutter / dart）
    runtime: Mapped[str] = mapped_column(String(20), nullable=False)

    # バージョン系列（例: 3.13 / 24）
    cycle: Mapped[str] = mapped_column(String(20), nullable=False)

    # その系列の最新のバージョン（例: 3.13.17）
    latest_version: Mapped[str] = mapped_column(String(50), nullable=False)

    # その系列の公開日（不明な場合は NULL）
    release_date: Mapped[date | None] = mapped_column(Date, nullable=True)

    # サポート終了日（Flutter・Dart など、期限が定められていないものは NULL）
    eol_date: Mapped[date | None] = mapped_column(Date, nullable=True)

    # サポートが終了しているか
    is_eol: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # 長期サポート（LTS）の系列か（Node.js の、偶数の系列を見分けるため）
    is_lts: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<RuntimeRelease {self.runtime} {self.cycle} latest={self.latest_version}>"


class RepoRuntime(Base):
    """リポジトリが使っている言語・実行環境（設定ファイルから検出したもの）。

    毎日のクロールで、スキャンしたリポジトリ単位に全置換する（設定ファイルが現在の正）。
    """

    __tablename__ = "repo_runtimes"
    __table_args__ = (
        UniqueConstraint(
            "repo_full_name", "runtime", "cycle", "source_path", name="uq_repo_runtimes",
        ),
        Index("ix_repo_runtimes_repo", "repo_full_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # 対象リポジトリ（例: baby-feelings/baby_grow）
    repo_full_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # 言語・実行環境（python / nodejs / flutter / dart）
    runtime: Mapped[str] = mapped_column(String(20), nullable=False)

    # 使っているバージョン系列（例: 3.13 / 24）
    cycle: Mapped[str] = mapped_column(String(20), nullable=False)

    # 由来の設定ファイルのパス（例: .github/workflows/ci.yml）
    source_path: Mapped[str] = mapped_column(String(1000), nullable=False)

    # 版を固定して使っているか。False は「この版以上」のような下限の指定
    # （package.json の engines など。実際に動いている版とは限らないため、警告の対象にしない）
    pinned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # 最後にスキャンで確認した日時
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<RepoRuntime {self.repo_full_name} {self.runtime} {self.cycle}>"


class RuntimeAlert(Base):
    """送信済みの、言語・実行環境の通知（同じ通知を二重に送らないための記録）。

    通知は、言語・系列ごとの出来事（新しい系列の公開・サポート終了が近い・サポート終了）で、
    `alert_key`（例: `eol_soon:python:3.11`）で一意にする。同じキーは、一度送ったら、送らない。
    `initialized` という特別なキーは、最初の実行で、既存の状況を記録だけして通知しなかった印。
    """

    __tablename__ = "runtime_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    alert_key: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)

    sent_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<RuntimeAlert {self.alert_key}>"
