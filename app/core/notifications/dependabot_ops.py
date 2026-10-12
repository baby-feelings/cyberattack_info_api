"""DEPSOPS（Dependabot PR 自動運用）の実行結果の通知。"""
from typing import Any

from app.core.notifications import recipients as recipient_resolver
from app.core.notifications.base import CRAWLER_LABELS, Notifier
from app.core.notifications.slack import truncate_for_slack


class DependabotOpsNotifier(Notifier):
    """DEPSOPS の実行結果（自動マージ・要確認）の通知。

    自動マージした PR・人の確認が必要な PR の両方を毎回通知する（監査性重視。
    merged/flagged が両方空の場合のみ送信をスキップする）。
    """

    def __init__(
        self,
        merged: list[dict[str, Any]],
        flagged: list[dict[str, Any]],
        recipients: list[str] | None = None,
    ) -> None:
        super().__init__(recipients)
        self._merged = merged
        self._flagged = flagged

    def has_content(self) -> bool:
        return bool(self._merged or self._flagged)

    def default_recipients(self) -> list[str]:
        return recipient_resolver.resolve_recipients("DEPSOPS")

    def build_message(self) -> str:
        emoji, label = CRAWLER_LABELS["DEPSOPS"]
        lines = [f"{emoji} *{label}*", ""]

        if self._merged:
            lines.append(f"✅ *自動マージ（{len(self._merged)}件）*")
            for item in self._merged:
                lines.append(f"• `{item['repo_full_name']}` #{item['pr_number']} {item['title']}")
            lines.append("")

        if self._flagged:
            lines.append(f"⚠️ *要確認（{len(self._flagged)}件）*")
            for item in self._flagged:
                lines.append(
                    f"• `{item['repo_full_name']}` #{item['pr_number']} {item['title']}"
                    f"（{item['reason']}）"
                )
        return truncate_for_slack("\n".join(lines).rstrip())


def notify_dependabot_ops(
    merged: list[dict[str, Any]],
    flagged: list[dict[str, Any]],
    *,
    recipients: list[str] | None = None,
) -> None:
    """DEPSOPS（Dependabot PR 自動運用）の実行結果を Slack に通知する。

    Args:
        merged: 自動マージした PR の辞書リスト（"repo_full_name"・"pr_number"・"title"）
        flagged: 自動マージしなかった PR の辞書リスト（上記に加え "reason"）
        recipients: 送信先を明示的に指定する場合に使う。省略時は
            GITHUB_USERNAME 自身の登録済みWebhookへ送る。
    """
    DependabotOpsNotifier(merged, flagged, recipients).send()
