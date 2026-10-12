"""認証・ユーザー別設定ドメインの ORM モデル定義。"""
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class UserAccount(Base):
    """GitHub ログイン済みユーザーのアカウント情報（Issue #227）。

    ログインのたびに `github_access_token_encrypted` を最新化する（トークンの
    リフレッシュ・失効検知を兼ねる）。`slack_webhook_url` はダッシュボードの
    設定画面から任意で登録する（未登録なら null、通知は送られない）。

    1行1ユーザー（`github_username` が主キー）。GITHUB_USERNAME（baby-feelings）
    自身もダッシュボードにログインすればここに1行できる点は他ユーザーと同じ扱い
    だが、baby-feelings 自身の毎日クロール（`app.depscan.crawler` 等）は環境変数
    駆動のまま変更しない。このテーブルが対象にするのは、
    「GITHUB_USERNAME 以外の登録済みユーザー自身のリポジトリ」に対する定期実行
    （`app.core.user_crawl_runner`）である。
    """

    __tablename__ = "user_accounts"

    # ログインした GitHub ユーザー名（login）
    github_username: Mapped[str] = mapped_column(String(255), primary_key=True)

    # GitHub OAuth アクセストークン（app.core.crypto で暗号化して保存）。
    # 登録済みユーザー自身のリポジトリをDEPSCAN/CODESCAN/DEPSOPSで定期的に
    # 再スキャンするために必要（ログイン直後のオンデマンドスキャン1回にしか
    # 使わなかった従来の使い方を、Issue #227で永続化に拡張した）
    github_access_token_encrypted: Mapped[str] = mapped_column(Text, nullable=False)

    # 登録済みSlack Incoming Webhook URL（未登録なら null）
    slack_webhook_url: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # 通知の有効/無効（Webhook登録済みでも一時的にオフにできるようにするためのフラグ。
    # 削除ではなくこちらをFalseにするだけでも通知を止められる）
    notifications_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False,
    )

    def __repr__(self) -> str:
        return (
            f"<UserAccount {self.github_username} "
            f"webhook={'set' if self.slack_webhook_url else 'unset'}>"
        )
