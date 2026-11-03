"""本アプリ自身の鍵（API キー・GitHub トークン）の更新期限の通知（Issue #406）。

鍵は、定期的に更新する（漏えいしても、被害の期間を限る）。更新の期限を設定で決め、期限の前から、
毎日、管理者（`GITHUB_USERNAME`）の Webhook に知らせる。
鍵の値そのものは、扱わない（名前と期限だけ）。
"""
from dataclasses import dataclass

from app.core.notifications import recipients as recipient_resolver
from app.core.notifications.base import Notifier
from app.core.notifications.slack import DASHBOARD_URL, truncate_for_slack


@dataclass(frozen=True)
class ExpiringSecret:
    """更新期限が近い（または過ぎた）鍵1件。"""

    name: str
    expires_on: str       # YYYY-MM-DD
    days_left: int        # 負なら、期限切れ
    how_to_rotate: str    # 更新の手順（1行）


class SecretExpiryNotifier(Notifier):
    """鍵の更新期限の通知。"""

    def __init__(self, secrets: list[ExpiringSecret], recipients: list[str] | None = None) -> None:
        super().__init__(recipients)
        self._secrets = secrets

    def has_content(self) -> bool:
        return bool(self._secrets)

    def default_recipients(self) -> list[str]:
        return recipient_resolver.resolve_admin_recipient()

    def build_message(self) -> str:
        lines = [":key: *本アプリの鍵の更新期限が近づいています*", ""]
        for secret in sorted(self._secrets, key=lambda s: s.days_left):
            if secret.days_left < 0:
                status = f":rotating_light: 期限切れ（{-secret.days_left}日前）"
            else:
                status = f":hourglass_flowing_sand: あと{secret.days_left}日"
            lines.append(
                f"• *{secret.name}*（期限 {secret.expires_on}）{status} — {secret.how_to_rotate}",
            )
        lines += [
            "",
            "更新したら、`.env.production` の期限（`*_EXPIRES_ON`）も、次の期限に更新する。",
            f">詳細: {DASHBOARD_URL}",
        ]
        return truncate_for_slack("\n".join(lines))
