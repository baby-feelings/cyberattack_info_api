"""アプリケーション設定モジュール。
.env ファイルから環境変数を読み込み、型安全な設定オブジェクトを提供する。
"""
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # データベース接続文字列（例: postgresql://user:pass@host/dbname）
    DATABASE_URL: str

    # API認証キー（X-API-KEY ヘッダーで受け取る固定キー。管理者用・フルアクセス）
    API_KEY: str

    # 公開ダッシュボード用の読み取り専用 API キー（X-API-KEY ヘッダー）。
    # React ダッシュボードのビルド成果物（VITE_ 環境変数）はブラウザに配信され誰でも
    # 抽出できるため、/admin/* も保護する API_KEY をダッシュボードに埋め込まない。
    # 未設定の場合、読み取り専用エンドポイントは API_KEY のみで認証される（後方互換）。
    PUBLIC_API_KEY: str = ""

    # 実行環境識別子（development / production）
    ENVIRONMENT: str = "development"

    # CISA KEV フィードURL（変更があった場合に環境変数で上書き可能）
    CISA_KEV_URL: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )

    # クローラーの実行時刻（UTC）
    CRON_HOUR_UTC: int = 19       # KEV: JST 4:00 = UTC 19:00
    CRON_MINUTE_UTC: int = 0
    OSV_CRON_HOUR_UTC: int = 20   # OSV: JST 5:00 = UTC 20:00
    JVN_CRON_HOUR_UTC: int = 21   # JVN: JST 6:00 = UTC 21:00

    # Slack 通知用 Webhook URL（未設定時は通知をスキップ）
    SLACK_WEBHOOK_URL: str = ""

    # OSV クローラー設定
    # 直近何日分の脆弱性を取得対象とするか（cutoff フィルター）
    OSV_DAYS: int = 30
    # OSV データの保持期間（日数）: この日数より古い modified レコードを定期削除する
    OSV_RETENTION_DAYS: int = 180

    # JVN クローラー設定
    # 直近何日分の脆弱性を取得対象とするか（dateLastModified フィルター）
    JVN_DAYS: int = 30
    # JVN データの保持期間（日数）: この日数より古い date_last_modified レコードを定期削除する
    JVN_RETENTION_DAYS: int = 180

    # 依存ライブラリ脆弱性スキャナー（DEPSCAN）設定
    # GitHub API 認証用 PAT（fine-grained, Contents: Read-only 推奨）
    GITHUB_TOKEN: str = ""
    # スキャン対象リポジトリのオーナー（GitHub ユーザー名）
    GITHUB_USERNAME: str
    # スキャン対象外のリポジトリ（カンマ区切りの `owner/name`。大文字小文字は区別しない）。
    # DEPSCAN・CODESCAN・DEPSOPS のすべてで対象外にする。すでにあるデータと起票済みの
    # Issue は、毎日のクリーンアップで片付ける（Issue #342。学習用の脆弱なアプリ等を想定）
    SCAN_EXCLUDE_REPOS: str = ""
    # 運用を停止したアプリのリポジトリ（カンマ区切りの `owner/name`。大文字小文字は区別しない）。
    # ダッシュボードの DEPSCAN・DEPSOPS・CODESCAN で「運用中」「運用停止中」に分けて見られる
    # ようにする。
    # スキャンは止めない（止めるのは SCAN_EXCLUDE_REPOS）。載っていないリポジトリは運用中として扱う
    INACTIVE_REPOS: str = ""
    # DEPSCAN: JST 7:00 = UTC 22:00（KEV→OSV→JVN の後段）
    DEPSCAN_CRON_HOUR_UTC: int = 22
    # DEPSCAN データの保持期間（日数）: 解決済み（resolved_at 設定済み）のまま
    # この日数を超えて経過したレコードのみ定期削除する（未解決レコードは対象外）
    DEPSCAN_RETENTION_DAYS: int = 180

    # 自アプリコード脆弱性診断（CODESCAN）設定
    # DEPSCAN の後段に配置: JST 7:30 = UTC 22:30
    CODESCAN_CRON_HOUR_UTC: int = 22
    CODESCAN_CRON_MINUTE_UTC: int = 30
    # CODESCAN データの保持期間（日数）: 解決済み（resolved_at 設定済み）のまま
    # この日数を超えて経過したレコードのみ定期削除する（未解決レコードは対象外）
    CODESCAN_RETENTION_DAYS: int = 180

    # ダッシュボードのURL（末尾スラッシュなし）。Slack通知・GitHub Issue のリンクと、
    # CORS で許可するオリジン（本番）に使う。ダッシュボードのドメインを変えたら、ここを変える
    DASHBOARD_URL: str = "https://cyberattackinfoapi.vercel.app"

    # 言語・実行環境のバージョン監視（RUNTIME）設定
    # CODESCAN の後段・DEPSOPS の前に配置: JST 7:45 = UTC 22:45
    RUNTIME_CRON_HOUR_UTC: int = 22
    RUNTIME_CRON_MINUTE_UTC: int = 45

    # Dependabot PR 自動運用（DEPSOPS）設定
    # JST 8:00 = UTC 23:00（DEPSCAN の後段。Dependabot が新規検知に反応する時間を確保）
    DEPSOPS_CRON_HOUR_UTC: int = 23
    # DEPSOPS データの保持期間（日数）: この日数より古い processed_at レコードを定期削除する
    DEPSOPS_RETENTION_DAYS: int = 180

    # 削除済みリポジトリのDEPSCAN/CODESCAN/DEPSOPSデータ削除（Issue #228）設定
    # DEPSOPSの後段: JST 8:15 = UTC 23:15
    REPO_CLEANUP_CRON_HOUR_UTC: int = 23
    REPO_CLEANUP_CRON_MINUTE_UTC: int = 15

    # GitHub ログイン（DEPSCAN ダッシュボードのアクセス制御）設定
    # OAuth App の Client ID / Secret（未設定時は /auth/github/* がエラーを返すのみで
    # アプリ全体は起動する。GITHUB_TOKEN 同様のソフトフェイル方針）
    GITHUB_OAUTH_CLIENT_ID: str = ""
    GITHUB_OAUTH_CLIENT_SECRET: str = ""
    # セッショントークン（JWT）の署名鍵。未設定のまま本番運用しないこと
    SESSION_SECRET_KEY: str = ""
    # OAuth コールバック後にリダイレクトするダッシュボードの URL
    FRONTEND_URL: str = "https://cyberattackinfoapi.vercel.app"
    # OAuth の redirect_uri 組み立てに使う、本 API 自身の公開 URL
    # （GitHub OAuth App の Authorization callback URL と scheme まで一致させる必要があるため、
    # リクエストヘッダーから動的に推測せず固定値を持つ）
    API_BASE_URL_FOR_OAUTH: str = "https://168.138.213.240.nip.io"

    # MCP サーバーを OAuth 2.1 の認可サーバーとして公開する際の issuer URL（Issue #303）。
    # 空なら OAuth 機能は無効（従来の貼り付け方式のトークンのみ）。ドメイン変更時はこの値を
    # 新しい公開 URL（https://...、末尾スラッシュなし）にする
    MCP_OAUTH_ISSUER: str = ""

    # 運用監視（Prometheus）用のメトリクスエンドポイント保護キー。
    # 未設定時は /metrics 自体を無効化する（他の外部連携機能と同じ opt-in パターン）
    METRICS_API_KEY: str = ""

    # ユーザー別Slack通知登録（Issue #227）設定
    # ログイン時に取得したGitHubアクセストークンをDBへ暗号化保存するためのFernet鍵
    # （`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
    # で生成）。未設定のまま本番運用しないこと（未設定時はトークンを保存できず、
    # 登録済みユーザーの定期スキャン機能が動作しない）
    TOKEN_ENCRYPTION_KEY: str = ""
    # 登録済みユーザー（GITHUB_USERNAME以外）のリポジトリに対するDEPSCAN/CODESCAN/
    # DEPSOPSの定期実行時刻（UTC）。DEPSOPSの後段: JST 8:30 = UTC 23:30
    USER_CRAWL_CRON_HOUR_UTC: int = 23
    USER_CRAWL_CRON_MINUTE_UTC: int = 30
    # MCPトークンの期限前通知: 毎日 UTC 23:45（JST 翌日 8:45）
    MCP_EXPIRY_NOTICE_CRON_HOUR_UTC: int = 23
    MCP_EXPIRY_NOTICE_CRON_MINUTE_UTC: int = 45
    # 使われない OAuth 接続・登録の自動整理: 毎日 UTC 23:50（JST 翌日 8:50）
    OAUTH_CLEANUP_CRON_HOUR_UTC: int = 23
    OAUTH_CLEANUP_CRON_MINUTE_UTC: int = 50

    # 脆弱性への対応期限（SLA。Issue #404）。検知日から、この日数以内に解決することを目標にする。
    # LOW・重要度不明は期限なし。KEV 掲載済みは SLA_KEV_DAYS に短縮する（重要度が低くても）
    SLA_CRITICAL_DAYS: int = 7
    SLA_HIGH_DAYS: int = 30
    SLA_MEDIUM_DAYS: int = 90
    SLA_KEV_DAYS: int = 7
    # MTTR（平均対応日数）を集計する、解決済みの期間（日）。解決済みの保持期間（180日）以内にする
    SLA_MTTR_WINDOW_DAYS: int = 90
    # 週次の対応状況まとめ（Slack）: 毎週月曜 UTC 0:00（JST 月曜 9:00）
    SLA_DIGEST_DAY_OF_WEEK: str = "mon"
    SLA_DIGEST_CRON_HOUR_UTC: int = 0
    SLA_DIGEST_CRON_MINUTE_UTC: int = 0

    # GitHub のセキュリティアラートの取り込み（Issue #402）: 毎日 UTC 22:50（言語監視の後）
    GHALERT_CRON_HOUR_UTC: int = 22
    GHALERT_CRON_MINUTE_UTC: int = 50

    # リポジトリの設定の監査（Issue #398）: 毎日 UTC 22:40（言語監視の前）
    REPOAUDIT_CRON_HOUR_UTC: int = 22
    REPOAUDIT_CRON_MINUTE_UTC: int = 40

    # 本アプリ自身の防御（Issue #406）
    # レート制限: 管理 API・認証系で、1分あたりの上限と、認証失敗の連続によるロックアウト
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_LOCKOUT_FAILURES: int = 10
    RATE_LIMIT_LOCKOUT_MINUTES: int = 15
    # 監査ログの保持期間（日）
    AUDIT_RETENTION_DAYS: int = 180
    # 鍵の更新期限（YYYY-MM-DD。空なら、通知しない）と、何日前から毎日通知するか
    API_KEY_EXPIRES_ON: str = ""
    GITHUB_TOKEN_EXPIRES_ON: str = ""
    SECRETS_EXPIRY_NOTICE_DAYS: int = 14
    # 鍵の更新期限の通知と、監査ログの掃除: 毎日 UTC 23:40
    SECRET_EXPIRY_CRON_HOUR_UTC: int = 23
    SECRET_EXPIRY_CRON_MINUTE_UTC: int = 40

    # コミットの監視（Issue #405）: 毎日 UTC 22:20。信頼するコミッター（管理者・dependabot・
    # github-actions 以外に足すユーザー。カンマ区切りの GitHub ログイン名）
    TRUSTED_COMMITTERS: str = ""
    # True にすると、信頼するユーザーでも、署名のないコミットを通知する（なりすまし対策。
    # 自分のコミットを、すべて署名している場合に使う）
    COMMITWATCH_REQUIRE_SIGNATURE: bool = False
    COMMITWATCH_CRON_HOUR_UTC: int = 22
    COMMITWATCH_CRON_MINUTE_UTC: int = 20

    # 公開サイトの外形監視（Issue #401）: 毎日 UTC 22:35。リポジトリの情報から自動検出するほかに、
    # 足りない URL（https）をカンマ区切りで追加できる（自分の所有するドメインのみ）
    EXTERNAL_MONITOR_URLS: str = ""
    EXTMON_CRON_HOUR_UTC: int = 22
    EXTMON_CRON_MINUTE_UTC: int = 35

    # 検知の例外（受容・誤検知・影響なし。Issue #403）
    # 受容の期限の上限（日）。期限なしの受容は認めない（放置を防ぐ）
    EXCEPTION_MAX_DAYS: int = 365
    # 期限の何日前に再通知するか
    EXCEPTION_EXPIRY_NOTICE_DAYS: int = 7
    # 期限切れ・修正版の公開の確認と通知: 毎日 UTC 22:55（DEPSCAN・CODESCAN・言語監視の後）
    EXCEPTION_CRON_HOUR_UTC: int = 22
    EXCEPTION_CRON_MINUTE_UTC: int = 55

    @field_validator("API_KEY_EXPIRES_ON", "GITHUB_TOKEN_EXPIRES_ON")
    @classmethod
    def _validate_expiry_date(cls, value: str) -> str:
        """鍵の更新期限は、YYYY-MM-DD か空にする（Fail Fast。誤りで、通知が止まらないように）。"""
        if value:
            from datetime import date

            try:
                date.fromisoformat(value)
            except ValueError:
                raise ValueError(f"更新期限は YYYY-MM-DD 形式で指定してください: {value}") from None
        return value

    @field_validator("SLA_CRITICAL_DAYS", "SLA_HIGH_DAYS", "SLA_MEDIUM_DAYS", "SLA_KEV_DAYS")
    @classmethod
    def _validate_sla_days(cls, value: int) -> int:
        """対応期限は 1 日以上にする（0 や負数だと、検知した瞬間に全件が期限超過になる）。"""
        if value < 1:
            raise ValueError(f"SLA の対応期限は 1 日以上で指定してください: {value}")
        return value

    @field_validator("SCAN_EXCLUDE_REPOS", "INACTIVE_REPOS")
    @classmethod
    def _validate_repo_list(cls, value: str) -> str:
        """`owner/name` 形式でない指定は、起動時に弾く（書き間違いに気づかない事故を防ぐ）。"""
        for entry in (e.strip() for e in value.split(",") if e.strip()):
            owner, _, name = entry.partition("/")
            if not owner or not name or "/" in name:
                raise ValueError(
                    "SCAN_EXCLUDE_REPOS・INACTIVE_REPOS は 'owner/name' を"
                    "カンマ区切りで指定してください: "
                    f"{entry!r}",
                )
        return value

    model_config = SettingsConfigDict(
        # 環境に応じて .env.development または .env.production を使用
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )


# シングルトンとしてアプリ全体で共有
# mypy は env_file からの値注入を認識できないため type: ignore を使用
settings = Settings()  # type: ignore[call-arg]
