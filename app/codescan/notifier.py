"""CODESCAN（自アプリのコード脆弱性）の新規検知の通知。"""
from collections import Counter
from typing import Any

from app.core.notifications import recipients as recipient_resolver
from app.core.notifications.base import CRAWLER_LABELS, Notifier
from app.core.notifications.slack import truncate_for_slack

# 重い順（通知の表示順）。ここに無い重要度は末尾に出す
_SEVERITY_ORDER = ("ERROR", "WARNING", "INFO")
# スキャナー名（検知の "tool"）の表示名
_TOOL_LABELS = {
    "semgrep": "Semgrep",
    "gitleaks": "Gitleaks",
    "zizmor": "Zizmor",
    "iac": "インフラ設定",
}


def _counts_text(counter: Counter[str], order: tuple[str, ...] | None = None) -> str:
    """`ERROR 2・WARNING 3` のような、件数の並びの文字列にする。"""
    ranks = {key: rank for rank, key in enumerate(order or ())}
    # 順序の指定に無いものは末尾に、名前順で並べる
    keys = sorted(counter, key=lambda k: (ranks.get(k, len(ranks)), k))
    return "・".join(f"{key} {counter[key]}" for key in keys)


class CodeFindingsNotifier(Notifier):
    """CODESCAN の新規検知を、リポジトリ別の件数の概要にした1通で通知する。

    findings は CodeFinding 相当の辞書のリスト（"repo_full_name"・"severity"・"tool" を使用）。
    行数が膨らまないよう、検知の個別の内容は載せず、リポジトリごとに重要度別・ツール別の件数だけを
    出す（個別の内容は、ダッシュボードと、起票した GitHub Issue で確認する）。
    """

    def __init__(
        self, new_findings: list[dict[str, Any]], recipients: list[str] | None = None,
    ) -> None:
        super().__init__(recipients)
        self._findings = new_findings

    def has_content(self) -> bool:
        return bool(self._findings)

    def default_recipients(self) -> list[str]:
        # 省略時は GITHUB_USERNAME 自身の登録済み Webhook へ送る（毎日クロールの既定経路）
        return recipient_resolver.resolve_recipients("CODESCAN")

    def build_message(self) -> str:
        emoji, label = CRAWLER_LABELS["CODESCAN"]
        by_repo: dict[str, list[dict[str, Any]]] = {}
        for finding in self._findings:
            by_repo.setdefault(finding["repo_full_name"], []).append(finding)

        lines = [f"{emoji} *{label}を{len(self._findings)}件検知（{len(by_repo)}リポジトリ）*", ""]
        for repo in sorted(by_repo):
            findings = by_repo[repo]
            severities = Counter(str(f.get("severity") or "不明") for f in findings)
            tools = Counter(
                _TOOL_LABELS.get(str(f.get("tool")), str(f.get("tool") or "不明")) for f in findings
            )
            lines.append(f"*{repo}*（{len(findings)}件）")
            lines.append(f"• 重要度: {_counts_text(severities, _SEVERITY_ORDER)}")
            lines.append(f"• ツール: {_counts_text(tools)}")
            lines.append("")
        lines.append("詳細はダッシュボードの「CODESCAN」を確認してください。")
        return truncate_for_slack("\n".join(lines).rstrip())


def notify_code_findings(
    new_findings: list[dict[str, Any]], *, recipients: list[str] | None = None,
) -> None:
    """CODESCAN の新規検知を Slack に、リポジトリ別の概要1通として通知する。

    Args:
        new_findings: 新規検知の辞書リスト
        recipients: 送信先を明示的に指定する場合に使う。省略時は GITHUB_USERNAME 自身の
            登録済みWebhookへ送る。
    """
    CodeFindingsNotifier(new_findings, recipients).send()
