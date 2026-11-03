"""脆弱性への対応状況（SLA・MTTR）の、週次のまとめの通知（Issue #404）。

期限を超えた検知の一覧と、平均対応日数を送る。自分のアプリの対応状況のため、送り先は、
管理者（`GITHUB_USERNAME`）自身の Webhook のみ（エラー通知・言語バージョンの通知と同じ方針）。
集計そのものは `app.sla.report` が行い、ここは受け取った結果を整形して送るだけにする
（このパッケージは、個別のドメインを知らない）。
"""
from typing import Any

from app.core.notifications import recipients as recipient_resolver
from app.core.notifications.base import Notifier
from app.core.notifications.slack import DASHBOARD_URL, truncate_for_slack

# Slack に出す、期限超過の検知・リポジトリの最大件数（多いと読まれなくなるため。残りは件数だけ示す）
_MAX_OVERDUE_ITEMS = 10
_MAX_REPOS = 5


def _mttr_text(mttr_days: float | None) -> str:
    return "—" if mttr_days is None else f"{mttr_days:g} 日"


class SlaDigestNotifier(Notifier):
    """対応状況の週次まとめ。

    Args:
        report: `SlaReportOut.model_dump()` 相当の辞書（"summary"・"by_repo"・"overdue"・
            "policy"・"mttr_window_days"）
    """

    def __init__(self, report: dict[str, Any], recipients: list[str] | None = None) -> None:
        super().__init__(recipients)
        self._report = report

    def has_content(self) -> bool:
        # 週次の定期報告のため、期限超過が0件でも「問題なし」を送る（止まっていないことも伝わる）
        return True

    def default_recipients(self) -> list[str]:
        return recipient_resolver.resolve_admin_recipient()

    def build_message(self) -> str:
        report = self._report
        summary = report["summary"]
        policy = report["policy"]
        overdue = report["overdue"]
        window = report["mttr_window_days"]

        icon = ":warning:" if summary["overdue"] else ":white_check_mark:"
        lines = [
            f"{icon} *脆弱性への対応状況（週次）*",
            "",
            f"• 未解決（期限あり）: *{summary['open_with_deadline']}件*"
            f"　うち期限超過: *{summary['overdue']}件*",
            f"• 直近{window}日の解決: {summary['resolved']}件"
            f"　平均対応日数（MTTR）: {_mttr_text(summary['mttr_days'])}",
            f"• 対応期限: CRITICAL {policy['critical_days']}日 / HIGH {policy['high_days']}日 / "
            f"MEDIUM {policy['medium_days']}日 / KEV掲載 {policy['kev_days']}日",
        ]

        if overdue:
            lines += ["", "*期限超過（超過日数が多い順）*"]
            for item in overdue[:_MAX_OVERDUE_ITEMS]:
                marks = ("🛑" if item["is_malicious"] else "") + ("[KEV]" if item["is_kev"] else "")
                lines.append(
                    f"• {marks}`{item['repo_full_name']}` {item['package_name']} "
                    f"{item['installed_version']}（{item['severity'] or '不明'}）"
                    f" — {item['overdue_days']}日超過（期限{item['deadline_days']}日）",
                )
            if len(overdue) > _MAX_OVERDUE_ITEMS:
                lines.append(f"…ほか {len(overdue) - _MAX_OVERDUE_ITEMS}件")

            repos = [r for r in report["by_repo"] if r["overdue"]][:_MAX_REPOS]
            lines += ["", "*リポジトリ別の期限超過*"]
            lines += [f"• `{r['repo_full_name']}`: {r['overdue']}件" for r in repos]

        lines += ["", f">詳細（「対応状況」）: {DASHBOARD_URL}"]
        return truncate_for_slack("\n".join(lines))
