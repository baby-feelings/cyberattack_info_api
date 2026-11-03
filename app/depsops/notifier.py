"""DEPSOPS（Dependabot PR 自動運用）の実行結果の通知。"""
from collections import Counter
from typing import Any

from app.core.notifications import recipients as recipient_resolver
from app.core.notifications.base import CRAWLER_LABELS, Notifier
from app.core.notifications.slack import truncate_for_slack


class DependabotOpsNotifier(Notifier):
    """DEPSOPS の実行結果（自動マージ・要確認）の通知。

    自動マージした PR・人の確認が必要な PR の両方を、件数の概要で毎回通知する
    （merged/flagged が両方空の場合のみ送信をスキップする）。PR 個別の内容は
    ダッシュボード（判定履歴）で確認する。
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

        # 行数が膨らまないよう、PR 単位ではなくリポジトリ単位の件数だけの概要にする
        if self._merged:
            by_repo = Counter(item["repo_full_name"] for item in self._merged)
            lines.append(f"✅ *自動マージ（{len(self._merged)}件・{len(by_repo)}リポジトリ）*")
            lines.extend(f"• `{repo}` {count}件" for repo, count in sorted(by_repo.items()))
            lines.append("")

        if self._flagged:
            by_repo = Counter(item["repo_full_name"] for item in self._flagged)
            by_reason = Counter(item["reason"] for item in self._flagged)
            lines.append(f"⚠️ *要確認（{len(self._flagged)}件・{len(by_repo)}リポジトリ）*")
            lines.extend(f"• {reason} {count}件" for reason, count in by_reason.most_common())
            lines.append("詳細はダッシュボードの「Dependabot運用状況」を確認してください。")
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
