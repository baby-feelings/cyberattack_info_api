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


class McpToken(Base):
    """発行済みの MCP アクセストークンの台帳（個別の失効・一覧・最終使用日時のため）。

    トークン本体（JWT）は保存しない。JWT の `jti` クレームにこの行の `id` を載せ、MCP 接続時に
    署名・期限に加えて、この行が存在し失効していないことを確認する（`app.auth.mcp_token_store`）。
    1ユーザーが複数のトークン（端末ごと等）を持てる。
    """

    __tablename__ = "mcp_tokens"

    # トークンID（UUID4。JWT の jti と同じ値）
    id: Mapped[str] = mapped_column(String(36), primary_key=True)

    # 発行したユーザーの GitHub ユーザー名（このトークンで参照できるのは本人所有リポジトリのみ）
    username: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # 失効日時（未失効なら null）。失効済みトークンでの接続は 401
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # 最終使用日時（MCP 接続で認証が通った最新の時刻。書き込みの頻度を抑えるため分単位で間引く）
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # 期限が近いことを Slack で通知した日時（1トークンにつき通知は1回。未通知なら null）
    expiry_notified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )


class OAuthClient(Base):
    """OAuth 2.1 の動的クライアント登録（RFC 7591）で登録されたクライアント（Issue #303）。

    MCP クライアント（Claude Code 等）は、ログイン前に `/register` を呼んで自分を登録する。
    登録しただけではデータは見えない（本人の GitHub ログインと同意が別途必要）。
    クライアント情報（SDK の `OAuthClientInformationFull`）は JSON 文字列で保存する。
    `client_secret` は SDK の仕様上クライアントへ返す必要があるため、そのまま保持する
    （公開クライアントは `token_endpoint_auth_method=none` で秘密を持たない）。
    """

    __tablename__ = "oauth_clients"

    # クライアントID（SDK が UUID4 で発行する）
    client_id: Mapped[str] = mapped_column(String(64), primary_key=True)

    # OAuthClientInformationFull の JSON
    client_info_json: Mapped[str] = mapped_column(Text, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True,
    )

    # 最後に認可・トークン交換に使われた日時（未使用の登録を自動削除する判定に使う）
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
