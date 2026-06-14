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

    # クローラーの実行時刻（JST 時間を UTC に換算: JST 4:00 = UTC 19:00 前日）
    CRON_HOUR_UTC: int = 19
    CRON_MINUTE_UTC: int = 0

    # Slack 通知用 Webhook URL（未設定時は通知をスキップ）
    SLACK_WEBHOOK_URL: str = ""

    model_config = SettingsConfigDict(
        # 環境に応じて .env.development または .env.production を使用
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )


# シングルトンとしてアプリ全体で共有
# mypy は env_file からの値注入を認識できないため type: ignore を使用
settings = Settings()  # type: ignore[call-arg]
