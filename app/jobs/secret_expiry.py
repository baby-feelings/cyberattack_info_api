"""本アプリ自身の鍵の更新期限の通知と、監査ログの保持期間の掃除（毎日の定期ジョブ。Issue #406）。"""
import logging
from datetime import date

from app.audit.recorder import delete_old_audit_logs
from app.core.config import settings
from app.core.notifications.secret_expiry import ExpiringSecret, SecretExpiryNotifier

logger = logging.getLogger(__name__)

# 鍵ごとの、設定名・表示名・更新の手順
_SECRETS = (
    ("API_KEY_EXPIRES_ON", "API_KEY（管理者用）",
     "新しい値を生成し、`.env.production` を更新して再デプロイ。"
     "利用側（GitHub Secrets・Prometheus 等）も更新"),
    ("GITHUB_TOKEN_EXPIRES_ON", "GITHUB_TOKEN",
     "GitHub で新しいトークンを発行（最小の権限）し、`.env.production` を更新して再デプロイ。"
     "古いものを削除"),
)


def expiring_secrets(today: date | None = None) -> list[ExpiringSecret]:
    """更新期限が `SECRETS_EXPIRY_NOTICE_DAYS` 日以内（過ぎたものを含む）の鍵。

    期限を決めていない鍵は、対象外。
    """
    today = today or date.today()
    found = []
    for setting_name, label, how_to in _SECRETS:
        value = getattr(settings, setting_name)
        if not value:
            continue
        days_left = (date.fromisoformat(value) - today).days
        if days_left <= settings.SECRETS_EXPIRY_NOTICE_DAYS:
            found.append(ExpiringSecret(label, value, days_left, how_to))
    return found


def run_secret_expiry_notice(today: date | None = None) -> bool:
    """期限が近い鍵を、管理者に知らせる。保持期間を過ぎた監査ログも、あわせて削除する。"""
    # 掃除の失敗で、通知を止めない
    try:
        delete_old_audit_logs()
    except Exception:  # noqa: BLE001 - 定期ジョブは、どんな失敗でもスケジューラを止めない
        logger.exception("Audit log cleanup failed")
    secrets = expiring_secrets(today)
    sent = SecretExpiryNotifier(secrets).send()
    logger.info("Secret expiry notice: expiring=%d sent=%s", len(secrets), sent)
    return sent
