"""言語・実行環境のバージョンの通知（新しい系列の公開・サポート終了が近い・サポート終了）。

毎日の通知にはせず、変化があったときだけ送る（判定と記録は `app.runtimes.alerts`）。送り先は、
管理者（`GITHUB_USERNAME`）自身の Webhook のみ。自分のアプリの設定の話で、無関係な登録ユーザーに
届く必要がないため（エラー通知と同じ方針）。
"""
from typing import Any

from app.core.notifications import recipients as recipient_resolver
from app.core.notifications.base import CRAWLER_LABELS, Notifier
from app.core.notifications.slack import DASHBOARD_URL, truncate_for_slack

# 通知の種類ごとの見出し（絵文字つき）。対応が急ぐものほど目立つ絵文字にする
_HEADINGS = {
    "eol": ":rotating_light: *サポートが終了しました*",
    "eol_soon": ":hourglass_flowing_sand: *サポート終了が近づいています*",
    "new_release": ":new: *新しい版が公開されました*",
}
# 表示する順番（対応が急ぐものを先に）
_ORDER = ("eol", "eol_soon", "new_release")


def _describe(alert: dict[str, Any]) -> str:
    """通知1件の本文（言語・系列・内容・使っているアプリ）。"""
    name = f"{alert['runtime_label']} {alert['cycle']}"
    kind = alert["kind"]
    if kind == "eol":
        detail = f"（{alert['eol_date']} に終了）"
    elif kind == "eol_soon":
        detail = f"（{alert['eol_date']} に終了。あと {alert['days_to_eol']} 日）"
    else:
        detail = f"（最新 {alert['latest_version']}）"
    repos = "、".join(f"`{r}`" for r in alert["repos"])
    return f"• *{name}* {detail}" + (f"　使っているアプリ: {repos}" if repos else "")


class RuntimeAlertNotifier(Notifier):
    """言語・実行環境のバージョンの通知。

    Args:
        alerts: 通知する内容の辞書リスト。"kind"（eol / eol_soon / new_release）・"runtime_label"・
            "cycle"・"repos"（使っているアプリ）と、種類ごとの "eol_date"・"days_to_eol"・
            "latest_version"
    """

    def __init__(self, alerts: list[dict[str, Any]], recipients: list[str] | None = None) -> None:
        super().__init__(recipients)
        self._alerts = alerts

    def has_content(self) -> bool:
        return bool(self._alerts)

    def default_recipients(self) -> list[str]:
        return recipient_resolver.resolve_admin_recipient()

    def build_message(self) -> str:
        emoji, label = CRAWLER_LABELS["RUNTIME"]
        lines = [f"{emoji} *{label}のお知らせ*", ""]
        for kind in _ORDER:
            group = [a for a in self._alerts if a["kind"] == kind]
            if not group:
                continue
            lines.append(_HEADINGS[kind])
            lines.extend(_describe(a) for a in group)
            lines.append("")
        lines.append(f">詳細（「言語・実行環境」）: {DASHBOARD_URL}")
        return truncate_for_slack("\n".join(lines))


def notify_runtime_alerts(
    alerts: list[dict[str, Any]], *, recipients: list[str] | None = None,
) -> bool:
    """言語・実行環境のバージョンの通知を Slack に送る。送信できたら True、無い・失敗は False。"""
    return RuntimeAlertNotifier(alerts, recipients).send()
