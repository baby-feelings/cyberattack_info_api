"""公開サイトの外形監視の悪化（新しい問題）の通知（Issue #401）。

自分のサイトの話のため、送り先は、管理者（`GITHUB_USERNAME`）自身の Webhook のみ。
個別のドメインを知らない（悪化した問題の辞書を受け取るだけ）。
外から来た文字列（URL・メッセージ）は、Slack の mrkdwn として無害化して埋め込む。
"""
from typing import Any

from app.core.notifications import recipients as recipient_resolver
from app.core.notifications.base import Notifier
from app.core.notifications.slack import DASHBOARD_URL, escape_mrkdwn, truncate_for_slack

# Slack に出す最大件数（残りは件数だけ示す）
_MAX_ITEMS = 15
_ICONS = {"ERROR": ":rotating_light:", "WARNING": ":warning:"}


class SiteAlertNotifier(Notifier):
    """外形監視の悪化の通知。

    Args:
        findings: 新しく見つかった問題。各要素は {"url", "rule", "severity", "message"}
    """

    def __init__(self, findings: list[dict[str, Any]], recipients: list[str] | None = None) -> None:
        super().__init__(recipients)
        self._findings = findings

    def has_content(self) -> bool:
        return bool(self._findings)

    def default_recipients(self) -> list[str]:
        return recipient_resolver.resolve_admin_recipient()

    def build_message(self) -> str:
        # 重大なもの（ERROR）を先に出す
        ordered = sorted(self._findings, key=lambda f: f["severity"] != "ERROR")
        lines = [
            ":globe_with_meridians: *公開サイトの点検で、新しい問題が見つかりました"
            f"（{len(ordered)}件）*",
            "",
        ]
        for item in ordered[:_MAX_ITEMS]:
            icon = _ICONS.get(item["severity"], ":information_source:")
            lines.append(f"{icon} `{escape_mrkdwn(item['url'])}` {escape_mrkdwn(item['message'])}")
        if len(ordered) > _MAX_ITEMS:
            lines.append(f"…ほか {len(ordered) - _MAX_ITEMS}件")
        lines += ["", f">一覧: {DASHBOARD_URL}"]
        return truncate_for_slack("\n".join(lines))
