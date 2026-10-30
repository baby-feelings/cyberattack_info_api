"""検知の例外（受容）の通知: 期限の7日前・期限切れ・修正版の公開による解除（Issue #403）。

自分のアプリの対応状況の話のため、送り先は、管理者（`GITHUB_USERNAME`）自身の Webhook のみ
（言語バージョン・対応状況のまとめと同じ方針）。「どの検知か」の整形は、呼び出し側
（`app.finding_exceptions`）が済ませた辞書を受け取るだけにする（このパッケージは個別のドメインを知らない）。
"""
from typing import Any

from app.core.notifications import recipients as recipient_resolver
from app.core.notifications.base import Notifier
from app.core.notifications.slack import DASHBOARD_URL, truncate_for_slack

# Slack に出す、種類ごとの最大件数（多いと読まれなくなるため。残りは件数だけ示す）
_MAX_PER_SECTION = 10

# (キー, 見出し) の並び。対応が急ぐ順（再び有効な検知になったものを先に）
_SECTIONS = (
    ("fixed", ":white_check_mark: *修正版が公開されたため、受容を解除しました*"),
    ("expired", ":rotating_light: *受容の期限が切れました（再び対応が必要です）*"),
    ("soon", ":hourglass_flowing_sand: *受容の期限が近づいています*"),
)


class ExceptionNoticeNotifier(Notifier):
    """受容の期限・解除の通知。

    Args:
        notices: {"fixed": [...], "expired": [...], "soon": [...]}。各要素は
            `{"repo_full_name", "label", "reason", "expires_at"}` の辞書（`label` は、
            検知の見出し。例: `lodash GHSA-xxxx`）。
    """

    def __init__(
        self, notices: dict[str, list[dict[str, Any]]], recipients: list[str] | None = None,
    ) -> None:
        super().__init__(recipients)
        self._notices = notices

    def has_content(self) -> bool:
        return any(self._notices.get(key) for key, _ in _SECTIONS)

    def default_recipients(self) -> list[str]:
        return recipient_resolver.resolve_admin_recipient()

    def build_message(self) -> str:
        lines: list[str] = []
        for key, heading in _SECTIONS:
            items = self._notices.get(key) or []
            if not items:
                continue
            lines += [heading]
            for item in items[:_MAX_PER_SECTION]:
                expiry = f"（期限 {item['expires_at']}）" if item.get("expires_at") else ""
                lines.append(
                    f"• `{item['repo_full_name']}` {item['label']}{expiry}"
                    f" — 理由: {item['reason']}",
                )
            if len(items) > _MAX_PER_SECTION:
                lines.append(f"…ほか {len(items) - _MAX_PER_SECTION}件")
            lines.append("")
        lines.append(f">詳細: {DASHBOARD_URL}")
        return truncate_for_slack("\n".join(lines))
