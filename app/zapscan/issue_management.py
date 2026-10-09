"""OWASP ZAP スキャン結果（zap-report.json）の GitHub Issue 自動起票。

DEPSCAN / CODESCAN と同じ「1リポジトリにつき常に1つの Open Issue に集約する」設計を
踏襲し、共通処理 `app.core.issue_filing.file_or_update_repo_issues` を使う。
ZAP 専用の固定タイトルにして DEPSCAN / CODESCAN の Issue と混同しないようにする。

ZAP は DB を持たず結果は JSON レポートのみのため、DEPSCAN のような「新規検知の判定」は
せず、実行のたびに閾値以上のアラートを Issue へ追記する（Issue が Open の間はコメント追記、
クローズ後は新規作成）。
"""
import json
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.issue_filing import file_or_update_repo_issues

# GitHub Issue自動起票時のタイトル（Open Issue検索の一致キーも兼ねる）
_ISSUE_TITLE = "🕷️ API の脆弱性が検出されました (OWASP ZAP)"

# ZAP の riskcode（0=Informational / 1=Low / 2=Medium / 3=High）
RISK_LABELS: dict[int, str] = {0: "Informational", 1: "Low", 2: "Medium", 3: "High"}

# 1アラートあたり本文に載せる検出URLの最大数（本文が肥大化しないようにする）
_MAX_URIS_PER_ALERT = 5


def parse_alerts(report_path: Path, min_risk: int) -> list[dict[str, Any]]:
    """zap-report.json から、リスクが min_risk 以上のアラートを抽出する。

    Args:
        report_path: ZAP が出力した JSON レポートのパス。
        min_risk: 起票対象とする最小の riskcode（2 なら Medium 以上）。

    Returns:
        リスクの高い順に並べたアラート辞書のリスト。
    """
    report = json.loads(report_path.read_text(encoding="utf-8"))
    alerts: list[dict[str, Any]] = []
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            risk = int(alert.get("riskcode", 0))
            if risk < min_risk:
                continue
            alerts.append(
                {
                    "name": alert.get("name") or alert.get("alert", ""),
                    "risk": risk,
                    "count": int(alert.get("count", 0)),
                    "cwe_id": alert.get("cweid", ""),
                    "solution": _strip_html(alert.get("solution", "")),
                    "uris": sorted({i.get("uri", "") for i in alert.get("instances", [])}),
                }
            )
    return sorted(alerts, key=lambda a: (-a["risk"], a["name"]))


def _strip_html(text: str) -> str:
    """ZAP のテキストに含まれる <p></p> タグを取り除く（Issue本文を読みやすくする）。"""
    return text.replace("<p>", "").replace("</p>", "\n").strip()


def _format_alert_lines(alerts: list[dict[str, Any]]) -> list[str]:
    """アラートを Markdown の箇条書きに整形する。"""
    lines = []
    for alert in alerts:
        uris = alert["uris"][:_MAX_URIS_PER_ALERT]
        more = len(alert["uris"]) - len(uris)
        uri_text = ", ".join(f"`{u}`" for u in uris) + (f" ほか{more}件" if more > 0 else "")
        cwe = f" (CWE-{alert['cwe_id']})" if alert["cwe_id"] not in ("", "-1", "0") else ""
        lines.append(
            f"• [{RISK_LABELS.get(alert['risk'], 'N/A')}] {alert['name']}{cwe}"
            f" — {alert['count']}件: {uri_text}"
        )
        if alert["solution"]:
            lines.append(f"  - 対策: {alert['solution']}")
    return lines


def file_github_issues(
    alerts: list[dict[str, Any]],
    repo_full_name: str,
    token: str | None = None,
) -> None:
    """ZAP のアラートを、対象リポジトリの GitHub Issue として起票・追記する。

    GitHub API の失敗は共通処理側で握りつぶす（ZAP スキャン自体の成否に影響させない）。

    Args:
        alerts: `parse_alerts` の戻り値。
        repo_full_name: Issue を作るリポジトリ（"owner/repo"）。
        token: Issue作成に使うトークン。省略時は `settings.GITHUB_TOKEN`。
    """
    if not alerts:
        return

    token = token if token is not None else settings.GITHUB_TOKEN
    # 共通処理は「リポジトリ単位でグルーピングした finding リスト」を受け取る形のため、
    # アラートに repo_full_name を付けて渡す
    snapshots = [{**alert, "repo_full_name": repo_full_name} for alert in alerts]

    def format_body(findings: list[dict[str, Any]]) -> str:
        return (
            "OWASP ZAP（API Scan）が API の脆弱性を検知しました。\n\n"
            + "\n".join(_format_alert_lines(findings))
            + "\n\n---\nスキャンは使い捨ての API コンテナ（ダミー鍵・外部通信なし）に対する"
            "ものです。誤検知の可能性があるため、内容を確認して対応を判断してください。"
        )

    file_or_update_repo_issues(snapshots, _ISSUE_TITLE, format_body, token, "ZAP")
