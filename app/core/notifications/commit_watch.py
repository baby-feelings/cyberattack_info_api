"""コミットの監視（見慣れないコミッター・ワークフローの危険な変更）の通知（Issue #405）。

自分のリポジトリの話のため、送り先は、管理者（`GITHUB_USERNAME`）自身の Webhook のみ。
個別のドメインを知らない（整形済みの辞書を受け取るだけ）。外から来た文字列
（コミットメッセージ・作者名）は、Slack の mrkdwn として無害化して埋め込む。
確認すべき手順（鍵の失効・トークンの再発行・履歴の確認）を添える。
"""
from typing import Any

from app.core.notifications import recipients as recipient_resolver
from app.core.notifications.base import Notifier
from app.core.notifications.slack import DASHBOARD_URL, escape_mrkdwn, truncate_for_slack

# Slack に出す最大件数（残りは件数だけ示す）
_MAX_ITEMS = 10

# 種類ごとの見出し（コミット単位ではない通知）
_NOTES = {
    "history_rewritten": ":rotating_light: **履歴が書き換えられました**（force push の兆候）",
    "truncated": ":information_source: 未確認のコミットがあります",
}

_PROCEDURE = (
    "*確認の手順*: ①コミットの作者に、心当たりがあるか確認する　②心当たりがなければ、"
    "**デプロイキー・トークンを失効し、再発行**する（GitHub のパスワード・2要素認証も見直す）　"
    "③ワークフローの変更は、差分を確認し、不要なら取り消す　④ほかのリポジトリの履歴・設定も確認する"
)


class CommitWatchNotifier(Notifier):
    """コミットの監視の通知。

    Args:
        alerts: 通知する変更。各要素は {"kind"（commit・history_rewritten・truncated）,
            "repo_full_name", "sha", "title"} と、commit のとき、さらに {"url", "author",
            "verified", "untrusted", "incomplete", "touches_workflow",
            "risky": [{"file", "description", "excerpt"}]}（commit 以外は、title だけを使う）
    """

    def __init__(self, alerts: list[dict[str, Any]], recipients: list[str] | None = None) -> None:
        super().__init__(recipients)
        self._alerts = alerts

    def has_content(self) -> bool:
        return bool(self._alerts)

    def default_recipients(self) -> list[str]:
        return recipient_resolver.resolve_admin_recipient()

    def build_message(self) -> str:
        # 履歴の書き換え・危険な内容を含むものを先に出す
        ordered = sorted(
            self._alerts, key=lambda a: a.get("kind") == "commit" and not a["risky"],
        )
        lines = [
            f":detective: *リポジトリのコミットに、通常と違う変更があります（{len(ordered)}件）*",
            "",
        ]
        for alert in ordered[:_MAX_ITEMS]:
            if alert.get("kind") in _NOTES:
                lines.append(
                    f"• `{escape_mrkdwn(alert['repo_full_name'])}` {_NOTES[alert['kind']]}"
                    f"（{escape_mrkdwn(alert['title'])}）",
                )
                continue
            reasons = []
            if alert["untrusted"]:
                reasons.append("見慣れないコミッター")
                reasons.append("署名あり" if alert["verified"] else "署名なし")
            if alert["touches_workflow"]:
                reasons.append("ワークフローを変更")
            if alert.get("incomplete"):
                reasons.append("差分を確認しきれません（変更ファイルが多い、または差分なし）")
            lines.append(
                f"• `{escape_mrkdwn(alert['repo_full_name'])}` {escape_mrkdwn(alert['sha'])}"
                f" 作者: `{escape_mrkdwn(alert['author'])}`（{'・'.join(reasons)}）"
                f" {escape_mrkdwn(alert['title'])}",
            )
            for risky in alert["risky"]:
                lines.append(
                    f"    :warning: {escape_mrkdwn(risky['file'])}: "
                    f"{escape_mrkdwn(risky['description'])}"
                    f" — `{escape_mrkdwn(risky['excerpt'])}`",
                )
        if len(ordered) > _MAX_ITEMS:
            lines.append(f"…ほか {len(ordered) - _MAX_ITEMS}件")
        lines += ["", _PROCEDURE, f">一覧: {DASHBOARD_URL}"]
        return truncate_for_slack("\n".join(lines))
