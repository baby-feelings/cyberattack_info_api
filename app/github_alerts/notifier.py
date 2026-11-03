"""GitHub の secret scanning アラート（履歴に残ったシークレット）の通知（Issue #402）。

新規に見つかったときだけ、管理者（`GITHUB_USERNAME`）自身の Webhook に送る。シークレットの値は、
そもそも保存していないため、通知にも含まれない。無効化・再発行の手順と、履歴の書き換えが必要な場合の
案内を添える（個別のドメインを知らない。整形済みの辞書を受け取るだけ）。
"""
from typing import Any

from app.core.notifications import recipients as recipient_resolver
from app.core.notifications.base import Notifier
from app.core.notifications.slack import DASHBOARD_URL, truncate_for_slack

# Slack に出す最大件数（残りは件数だけ示す）
_MAX_ITEMS = 10


class GithubAlertNotifier(Notifier):
    """新規の secret scanning アラートの通知。

    Args:
        alerts: `GithubAlert` を辞書にしたもの（"repo_full_name"・"title"・"html_url"・
            "severity"・"detail"）の一覧
    """

    def __init__(self, alerts: list[dict[str, Any]], recipients: list[str] | None = None) -> None:
        super().__init__(recipients)
        self._alerts = alerts

    def has_content(self) -> bool:
        return bool(self._alerts)

    def default_recipients(self) -> list[str]:
        return recipient_resolver.resolve_admin_recipient()

    def build_message(self) -> str:
        # 有効（まだ使える）なシークレットを先に出す
        ordered = sorted(self._alerts, key=lambda a: a.get("severity") != "CRITICAL")
        lines = [
            f":rotating_light: *GitHub が、リポジトリにシークレットの漏えいを検知しました"
            f"（{len(ordered)}件）*",
            "",
        ]
        for alert in ordered[:_MAX_ITEMS]:
            leaked = "・公開された可能性あり" if alert["detail"].get("publicly_leaked") else ""
            lines.append(
                f"• `{alert['repo_full_name']}` {alert['title']}{leaked}"
                f" <{alert['html_url']}|詳細>",
            )
        if len(ordered) > _MAX_ITEMS:
            lines.append(f"…ほか {len(ordered) - _MAX_ITEMS}件")
        lines += [
            "",
            "*対応*: ①発行元でシークレットを**無効化・再発行**する（コードから消すだけでは、"
            "履歴から読み取れます）　②新しい値を、環境変数・シークレット管理で渡す　"
            "③履歴に残っている場合は、履歴の書き換え（`git filter-repo` 等）も検討する"
            "（無効化が先です）",
            f">一覧: {DASHBOARD_URL}",
        ]
        return truncate_for_slack("\n".join(lines))
