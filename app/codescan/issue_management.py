"""CODESCAN 検知結果の GitHub Issue 自動起票。

DEPSCAN の `app.depscan.issue_management` と同じ「1リポジトリにつき常に1つの
Open Issue に集約する」設計を踏襲するが、CODESCAN 専用の固定タイトル文字列を
使うことで DEPSCAN の Issue と混同しないようにする。CODESCAN は
`app.core.crawler_runner.run_crawler` を使う関係で Issue クローズ判定の
トリガーが DEPSCAN（再スキャン検証後）と同じタイミングでは持てないため、
本バージョンでは新規起票・追記のみを実装する（クローズは Issue 側で手動運用、
または将来の拡張で対応する）。
"""
import logging
from typing import Any

import httpx

from app.core.config import settings
from app.core.notifications import DASHBOARD_URL
from app.crawler_logs.writer import now_utc
from app.depscan.github_client import add_issue_comment, create_issue, find_open_issue

logger = logging.getLogger(__name__)

# GitHub Issue自動起票時のタイトル（Open Issue検索の一致キーも兼ねる）。
# DEPSCANのIssueタイトル（"依存ライブラリの脆弱性が検出されました (DEPSCAN)"）と
# 混同しないよう、CODESCAN専用の固定文字列にする
_ISSUE_TITLE = "🔎 自アプリのコード脆弱性が検出されました (CODESCAN)"

# 重大度の表示順（数値が小さいほど深刻）
_SEVERITY_ORDER: dict[str, int] = {"ERROR": 0, "WARNING": 1, "INFO": 2}


def _severity_rank(severity: str) -> int:
    return _SEVERITY_ORDER.get(severity.upper(), len(_SEVERITY_ORDER))


def _format_finding_lines(findings: list[dict[str, Any]]) -> list[str]:
    """1リポジトリ分の CodeFinding 相当の辞書を、重大度が高い順に整形する。"""

    def sort_key(f: dict[str, Any]) -> tuple[int, str, int]:
        return (_severity_rank(f.get("severity", "")), f["file_path"], f["line_start"])

    lines = []
    for finding in sorted(findings, key=sort_key):
        cvss = finding.get("cvss_score")
        cvss_text = f"CVSS {cvss:.1f}" if cvss is not None else "CVSS未算出"
        lines.append(
            f"• `{finding['file_path']}:{finding['line_start']}` "
            f"[{finding.get('severity', 'N/A')}] {cvss_text} — "
            f"{finding.get('rule_id', '')}: {finding.get('message', '')}"
        )
    return lines


def _file_github_issues(new_snapshots: list[dict[str, Any]]) -> None:
    """新規検知を、検知されたリポジトリ自身に GitHub Issue として自動起票する。

    同名の Open な Issue が既にあればコメントを追記し、無ければ新規作成する。
    GitHub API 呼び出しが失敗しても（Issues 書き込み権限が無いトークン等）、
    CODESCAN 全体の成功を妨げないようリポジトリ単位で例外を握りつぶす
    （DEPSCAN と同じ方針）。
    """
    if not new_snapshots:
        return

    by_repo: dict[str, list[dict[str, Any]]] = {}
    for finding in new_snapshots:
        by_repo.setdefault(finding["repo_full_name"], []).append(finding)

    timestamp = now_utc().strftime("%Y-%m-%d %H:%M UTC")
    token = settings.GITHUB_TOKEN

    for full_name, findings in by_repo.items():
        owner, repo = full_name.split("/", 1)
        body = (
            f"CODESCAN（Semgrep静的解析）が自アプリのコード脆弱性を検知しました"
            f"（{timestamp}）。\n\n"
            + "\n".join(_format_finding_lines(findings))
            + f"\n\n---\n詳細: {DASHBOARD_URL}"
        )
        try:
            issue_number = find_open_issue(owner, repo, _ISSUE_TITLE, token)
            if issue_number is not None:
                add_issue_comment(owner, repo, issue_number, body, token)
                logger.info(
                    "CODESCAN: added comment to existing issue #%d in %s",
                    issue_number, full_name,
                )
            else:
                issue = create_issue(owner, repo, _ISSUE_TITLE, body, token)
                logger.info("CODESCAN: created issue #%s in %s", issue.get("number"), full_name)
        except httpx.HTTPError as exc:
            logger.warning("CODESCAN: failed to file GitHub issue for %s: %s", full_name, exc)
