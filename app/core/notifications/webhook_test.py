"""Slack Webhook 登録時のテスト送信（Issue #227）。"""
from app.core.notifications.base import Notifier
from app.core.notifications.slack import DASHBOARD_URL


class WebhookRegistrationNotifier(Notifier):
    """登録しようとしている Webhook へ、通知が有効になったことを知らせる。"""

    def __init__(self, webhook_url: str, username: str) -> None:
        super().__init__([webhook_url])
        self._username = username

    def has_content(self) -> bool:
        return True

    def default_recipients(self) -> list[str]:
        return []  # 常に明示指定される

    def build_message(self) -> str:
        return (
            ":white_check_mark: *通知テスト*\n"
            f">{self._username} さんのアカウントでSlack通知が有効になりました。\n"
            f">詳細: {DASHBOARD_URL}"
        )


def send_test_notification(webhook_url: str, username: str) -> bool:
    """Webhook登録時のテスト送信。送信に成功したかどうかを返す
    （設定画面はこの結果を見てから登録を確定するかどうかを判断する）。
    """
    return WebhookRegistrationNotifier(webhook_url, username).send()
