"""CODESCAN 検知結果の GitHub Issue 自動起票。

DEPSCAN の `app.depscan.issue_management` と同じ「1リポジトリにつき常に1つの
Open Issue に集約する」設計を踏襲するが、CODESCAN 専用の固定タイトル文字列を
使うことで DEPSCAN の Issue と混同しないようにする。

クローズ（`close_resolved_repo_issues`）は、スキャンのたびに、全ツールの検査に成功したリポジトリで、
「対応が必要な検知（受容などの例外を除く）が0件か」で判定する。ツールが一部でも失敗した
リポジトリは、検知が減ったのではなく検査できなかっただけのため、判定の対象にしない。
"""
import logging
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.codescan.models import CodeFinding
from app.core.config import settings
from app.core.github.repo import GitHubRepo
from app.core.issue_filing import file_or_update_repo_issues
from app.core.notifications.slack import DASHBOARD_URL
from app.crawler_logs.writer import now_utc
from app.finding_exceptions.matching import not_excepted
from app.finding_exceptions.models import KIND_CODE

logger = logging.getLogger(__name__)

# GitHub Issue自動起票時のタイトル（Open Issue検索の一致キーも兼ねる）。
# DEPSCANのIssueタイトル（"依存ライブラリの脆弱性が検出されました (DEPSCAN)"）と
# 混同しないよう、CODESCAN専用の固定文字列にする
ISSUE_TITLE = "🔎 自アプリのコード脆弱性が検出されました (CODESCAN)"

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


def file_github_issues(new_snapshots: list[dict[str, Any]], token: str | None = None) -> None:
    """新規検知を、検知されたリポジトリ自身に GitHub Issue として自動起票する。

    同名の Open な Issue が既にあればコメントを追記し、無ければ新規作成する。
    GitHub API 呼び出しが失敗しても（Issues 書き込み権限が無いトークン等）、
    CODESCAN 全体の成功を妨げないようリポジトリ単位で例外を握りつぶす
    （DEPSCAN と同じ方針）。

    Args:
        token: Issue作成に使うGitHub PAT。省略時は`settings.GITHUB_TOKEN`
            （baby-feelings向け毎日クロールの既定）。登録済み他ユーザー自身の
            リポジトリに対して起票する場合（Issue #227）は、そのユーザー自身の
            OAuthアクセストークンを明示的に渡す必要がある
            （GITHUB_TOKENには他ユーザーのプライベートリポジトリへの書き込み権限が無いため）。
    """
    if not new_snapshots:
        return

    timestamp = now_utc().strftime("%Y-%m-%d %H:%M UTC")
    token = token if token is not None else settings.GITHUB_TOKEN

    def format_body(findings: list[dict[str, Any]]) -> str:
        return (
            f"CODESCAN（Semgrep静的解析）が自アプリのコード脆弱性を検知しました"
            f"（{timestamp}）。\n\n"
            + "\n".join(_format_finding_lines(findings))
            + f"\n\n---\n詳細: {DASHBOARD_URL}"
        )

    file_or_update_repo_issues(new_snapshots, ISSUE_TITLE, format_body, token, "CODESCAN")


def close_resolved_repo_issues(
    db: Session, candidate_repos: set[str], token: str | None = None,
) -> None:
    """対応が必要な検知が0件のリポジトリの、Open な CODESCAN Issue をクローズする。

    判定は、Issue 本文の個々の検知ではなく、「そのリポジトリに、未解決で、例外（受容・誤検知・
    影響なし）でない検知が残っているか」で行う（DEPSCAN と同じ）。`candidate_repos` は、
    全ツールの検査に成功したリポジトリ（失敗したツールがあると、検知が減ったのか検査できなかったのか
    区別できないため、呼び出し側で除く）。Open な Issue が無いリポジトリは、何もしない。
    GitHub への書き込みの失敗は、リポジトリ単位で握りつぶし、スキャン全体を失敗させない。

    Args:
        token: 省略時は `settings.GITHUB_TOKEN`（管理者のリポジトリ用）。登録済み他ユーザーの
            リポジトリでは、そのユーザー自身のトークンを渡す。
    """
    if not candidate_repos:
        return

    token = token if token is not None else settings.GITHUB_TOKEN
    timestamp = now_utc().strftime("%Y-%m-%d %H:%M UTC")

    for full_name in sorted(candidate_repos):
        remaining = not_excepted(
            db.query(CodeFinding).filter(
                CodeFinding.repo_full_name == full_name, CodeFinding.resolved_at.is_(None),
            ),
            KIND_CODE,
        ).count()
        if remaining > 0:
            continue

        repo = GitHubRepo.from_full_name(full_name, token)
        try:
            issue_number = repo.find_open_issue(ISSUE_TITLE)
            if issue_number is None:
                continue
            repo.add_issue_comment(
                issue_number,
                f"対応が必要なコードの指摘（受容などの例外を除く）が0件になったため自動的にクローズします"
                f"（{timestamp}）。",
            )
            repo.close_issue(issue_number)
            logger.info(
                "CODESCAN: closed issue #%d in %s (0 unresolved findings)", issue_number, full_name,
            )
        except httpx.HTTPError as exc:
            logger.warning("CODESCAN: failed to close GitHub issue for %s: %s", full_name, exc)
