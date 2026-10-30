"""DEPSCAN（依存ライブラリ脆弱性）の新規検知の通知。"""
from typing import Any

from app.core.finding_format import format_malicious_section, format_package_lines, split_malicious
from app.core.notifications import recipients as recipient_resolver
from app.core.notifications.base import CRAWLER_LABELS, Notifier
from app.core.notifications.slack import truncate_for_slack


class DependencyFindingsNotifier(Notifier):
    """依存ライブラリ脆弱性の新規検知を、リポジトリ別にグルーピングした1通のダイジェストで通知する。

    findings は DependencyFinding 相当のフィールドを持つ辞書のリスト
    （"repo_full_name"・"package_name"・"installed_version"・"severity"・"fixed_versions"・
    "osv_id" を使用。ORM セッションクローズ後の DetachedInstanceError を避けるため、
    ORM オブジェクトではなく辞書で受け取る）。
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
        return recipient_resolver.resolve_recipients("DEPSCAN")

    def build_message(self) -> str:
        emoji, label = CRAWLER_LABELS["DEPSCAN"]
        by_repo: dict[str, list[dict[str, Any]]] = {}
        for finding in self._findings:
            by_repo.setdefault(finding["repo_full_name"], []).append(finding)

        lines = [f"{emoji} *{label}を{len(self._findings)}件検知*", ""]
        for repo in sorted(by_repo):
            lines.append(f"*{repo}*")
            lines.extend(format_package_lines(by_repo[repo]))
            lines.append("")
        return truncate_for_slack("\n".join(lines).rstrip())


class MaliciousPackageNotifier(DependencyFindingsNotifier):
    """悪意あるパッケージの検知を、通常の脆弱性のダイジェストとは別の、専用の1通で通知する。

    マルウェアは更新ではなく削除と認証情報の再発行が必要で、緊急度が高いため、
    ダイジェストに埋もれないよう対応手順つきで先に送る。
    """

    def build_message(self) -> str:
        by_repo: dict[str, list[dict[str, Any]]] = {}
        for finding in self._findings:
            by_repo.setdefault(finding["repo_full_name"], []).append(finding)

        lines = [":skull_and_crossbones: *【緊急】悪意あるパッケージを検知*", ""]
        for repo in sorted(by_repo):
            lines.append(f"*{repo}*")
            lines.extend(format_malicious_section(by_repo[repo]))
            lines.append("")
        return truncate_for_slack("\n".join(lines).rstrip())


def notify_dependency_findings(
    new_findings: list[dict[str, Any]], *, recipients: list[str] | None = None,
) -> None:
    """依存ライブラリ脆弱性の新規検知を Slack に1通のダイジェストとして通知する。
    リポジトリ別にグルーピングし、findings が空なら何もしない。悪意あるパッケージ（`MAL-*`）は
    通常の脆弱性と別の、対応手順つきの緊急通知にする。

    Args:
        new_findings: DependencyFinding 相当のフィールドを持つ辞書のリスト
        recipients: 送信先を明示的に指定する場合に使う。省略時は
            GITHUB_USERNAME 自身の登録済みWebhookへ送る（毎日クロールの既定経路）。
    """
    # 悪意あるパッケージは、ダイジェストに混ぜず、緊急の専用通知として先に送る
    malicious, others = split_malicious(new_findings)
    MaliciousPackageNotifier(malicious, recipients).send()
    DependencyFindingsNotifier(others, recipients).send()
