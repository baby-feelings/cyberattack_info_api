"""アプリケーション設定モジュール。
.env ファイルから環境変数を読み込み、型安全な設定オブジェクトを提供する。
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # データベース接続文字列（例: postgresql://user:pass@host/dbname）
    DATABASE_URL: str

    # API認証キー（X-API-KEY ヘッダーで受け取る固定キー）
    API_KEY: str

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

    # KEV データの保持期間（日数）: この日数より古い date_added レコードを定期削除する
    KEV_RETENTION_DAYS: int = 180

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
    # DEPSCAN: JST 7:00 = UTC 22:00（KEV→OSV→JVN の後段）
    DEPSCAN_CRON_HOUR_UTC: int = 22

    # Dependabot PR 自動運用（DEPSOPS）設定
    # JST 8:00 = UTC 23:00（DEPSCAN の後段。Dependabot が新規検知に反応する時間を確保）
    DEPSOPS_CRON_HOUR_UTC: int = 23

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
    API_BASE_URL_FOR_OAUTH: str = "https://cyberattack-info-api.onrender.com"

    model_config = SettingsConfigDict(
        # 環境に応じて .env.development または .env.production を使用
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )


# シングルトンとしてアプリ全体で共有
# mypy は env_file からの値注入を認識できないため type: ignore を使用
settings = Settings()  # type: ignore[call-arg]
