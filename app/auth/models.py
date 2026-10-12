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

    # OAuth 2.1 で発行されたトークンなら、発行先クライアントのID（手動発行なら null）。
    # OAuth のトークンは短命（1時間）で頻繁に発行されるため、手動発行トークンの一覧・上限・
    # 期限前通知の対象から外す（Issue #303）
    oauth_client_id: Mapped[str | None] = mapped_column(String(64), nullable=True)


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


class OAuthAuthorization(Base):
    """OAuth 2.1 の認可リクエスト〜認可コードの1件分（Issue #303）。

    1行が次の順に進む。
    1. `/authorize` で作成（`username`・`code_hash` は null。同意画面と GitHub ログインの待ち）
    2. 本人の GitHub ログイン完了で `username` と `code_hash` を設定し、期限を認可コード用に更新
    3. `/token` での交換時に削除（認可コードは一度しか使えない）
    認可コード本体は保存せず、SHA-256 のハッシュだけを持つ。
    """

    __tablename__ = "oauth_authorizations"

    # 認可リクエストID（同意画面の URL に載せる推測不能な値）
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    redirect_uri: Mapped[str] = mapped_column(Text, nullable=False)
    redirect_uri_provided_explicitly: Mapped[bool] = mapped_column(Boolean, nullable=False)
    # クライアントが渡した state（そのままリダイレクト先へ返す）
    state: Mapped[str | None] = mapped_column(Text, nullable=True)
    code_challenge: Mapped[str] = mapped_column(String(128), nullable=False)
    # 空白区切りのスコープ
    scope: Mapped[str] = mapped_column(String(255), nullable=False)
    # RFC 8707 のリソース指標（null か、この MCP サーバーの URL）
    resource: Mapped[str | None] = mapped_column(Text, nullable=True)

    # 認可した本人（GitHub ユーザー名）と、認可コードのハッシュ。ログイン完了までは null
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)
    code_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True)

    # 同意画面を最初に開いたブラウザの識別（Cookie の乱数のハッシュ）。許可・拒否の送信は
    # このブラウザだけが行える（別の人が認可リクエストの URL を入手しても承認できない）
    browser_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True,
    )


class OAuthRefreshToken(Base):
    """OAuth 2.1 のリフレッシュトークン（Issue #303）。トークン本体は保存せず、SHA-256 のみ持つ。

    使うたびに新しいトークンへ交換（ローテーション）し、元のトークンは `used_at` を付けて残す。
    使用済みのトークンが再び提示されたら盗用の疑いとして、同じ `family_id`（最初の認可から
    連なる系統）をすべて失効する。
    """

    __tablename__ = "oauth_refresh_tokens"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    # 最初の認可から連なる系統のID（ローテーションしても変わらない）
    family_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    client_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # 認可した本人（GitHub ユーザー名）
    username: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    scope: Mapped[str] = mapped_column(String(255), nullable=False)
    resource: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # 交換済み（ローテーションで使用済み）の日時
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # 失効日時（本人の接続解除・/revoke・盗用の疑いによる系統の失効）
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
