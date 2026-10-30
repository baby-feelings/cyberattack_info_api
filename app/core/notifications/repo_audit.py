"""リポジトリの設定の変化（デプロイキー・Webhook・共同編集者の追加・削除）の通知（Issue #398）。

自分のアプリの設定の話のため、送り先は、管理者（`GITHUB_USERNAME`）自身の Webhook のみ。
個別のドメインを知らない（リポジトリごとの変化の辞書を受け取るだけ）。
"""
from app.core.notifications import recipients as recipient_resolver
from app.core.notifications.base import Notifier
from app.core.notifications.slack import DASHBOARD_URL, truncate_for_slack

_KIND_LABELS = {"keys": "デプロイキー", "hooks": "Webhook", "collaborators": "共同編集者"}
_CHANGE_LABELS = {"added": "追加", "removed": "削除"}
# Slack に出す最大件数（残りは件数だけ示す）
_MAX_ITEMS = 15


class RepoAuditChangeNotifier(Notifier):
    """設定の変化の通知。

    Args:
        changes: {リポジトリ: [{"kind", "change", "name"}, ...]}
    """

    def __init__(
        self, changes: dict[str, list[dict[str, str]]], recipients: list[str] | None = None,
    ) -> None:
        super().__init__(recipients)
        self._changes = changes

    def has_content(self) -> bool:
        return any(self._changes.values())

    def default_recipients(self) -> list[str]:
        return recipient_resolver.resolve_admin_recipient()

    def build_message(self) -> str:
        lines = [
            ":warning: *リポジトリの設定に、変化がありました*"
            "（身に覚えがなければ、乗っ取りの兆候かもしれません）",
            "",
        ]
        shown = 0
        total = sum(len(items) for items in self._changes.values())
        for repo, items in sorted(self._changes.items()):
            for item in items:
                if shown >= _MAX_ITEMS:
                    break
                shown += 1
                lines.append(
                    f"• `{repo}` {_KIND_LABELS.get(item['kind'], item['kind'])}を"
                    f"{_CHANGE_LABELS.get(item['change'], item['change'])}: `{item['name']}`",
                )
        if total > shown:
            lines.append(f"…ほか {total - shown}件")
        lines += ["", f">詳細: {DASHBOARD_URL}"]
        return truncate_for_slack("\n".join(lines))
