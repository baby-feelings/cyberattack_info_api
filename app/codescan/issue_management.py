"""CODESCAN 検知結果の GitHub Issue 自動起票。

DEPSCAN と同じ「1リポジトリにつき常に1つの Open Issue に集約する」設計で、共通の手順は
`app.core.issue_filing.IssueReporter`（Template Method）にある。ここには CODESCAN 固有の差分
（タイトル・本文・未解決の数え方）だけを置き、CODESCAN 専用の固定タイトル文字列で
DEPSCAN の Issue と混同しないようにする。

クローズ（`close_resolved_repo_issues`）は、スキャンのたびに、全ツールの検査に成功したリポジトリで、
「対応が必要な検知（受容などの例外を除く）が0件か」で判定する。ツールが一部でも失敗した
リポジトリは、検知が減ったのではなく検査できなかっただけのため、判定の対象にしない。
"""
from typing import Any

from sqlalchemy.orm import Session

from app.codescan.models import CodeFinding
from app.core.issue_filing import IssueReporter
from app.core.notifications.slack import DASHBOARD_URL
from app.finding_exceptions.matching import not_excepted
from app.finding_exceptions.models import KIND_CODE

# GitHub Issue自動起票時のタイトル（Open Issue検索の一致キーも兼ねる）。
# DEPSCANのIssueタイトル（"依存ライブラリの脆弱性が検出されました (DEPSCAN)"）と
# 混同しないよう、CODESCAN専用の固定文字列にする
ISSUE_TITLE = "🔎 自アプリのコード脆弱性が検出されました (CODESCAN)"

# 重大度の表示順（数値が小さいほど深刻）
_SEVERITY_ORDER: dict[str, int] = {"ERROR": 0, "WARNING": 1, "INFO": 2}


def _severity_rank(severity: str) -> int:
    return _SEVERITY_ORDER.get(severity.upper(), len(_SEVERITY_ORDER))


def _finding_sort_key(f: dict[str, Any]) -> tuple[int, str, int]:
    """重大度が高い順、次にファイルパス、行番号の順。"""
    return (_severity_rank(f.get("severity", "")), f["file_path"], f["line_start"])


def _format_finding_lines(findings: list[dict[str, Any]]) -> list[str]:
    """1リポジトリ分の CodeFinding 相当の辞書を、重大度が高い順に整形する。"""
    lines = []
    for finding in sorted(findings, key=_finding_sort_key):
        cvss = finding.get("cvss_score")
        cvss_text = f"CVSS {cvss:.1f}" if cvss is not None else "CVSS未算出"
        lines.append(
            f"• `{finding['file_path']}:{finding['line_start']}` "
            f"[{finding.get('severity', 'N/A')}] {cvss_text} — "
            f"{finding.get('rule_id', '')}: {finding.get('message', '')}"
        )
    return lines


class CodescanIssueReporter(IssueReporter):
    """CODESCAN（自アプリのコード脆弱性）の Issue の起票とクローズ。"""

    source = "CODESCAN"
    issue_title = ISSUE_TITLE
    resolved_subject = "コードの指摘"

    def format_body(self, findings: list[dict[str, Any]], timestamp: str) -> str:
        return (
            f"CODESCAN（Semgrep静的解析）が自アプリのコード脆弱性を検知しました"
            f"（{timestamp}）。\n\n"
            + "\n".join(_format_finding_lines(findings))
            + f"\n\n---\n詳細: {DASHBOARD_URL}"
        )

    def unresolved_count(self, db: Session, full_name: str) -> int:
        # 例外（受容・誤検知・影響なし）にした検知は、対応が要らないため、残りに数えない
        return not_excepted(
            db.query(CodeFinding).filter(
                CodeFinding.repo_full_name == full_name, CodeFinding.resolved_at.is_(None),
            ),
            KIND_CODE,
        ).count()


_reporter = CodescanIssueReporter()


def file_github_issues(new_snapshots: list[dict[str, Any]], token: str | None = None) -> None:
    """新規検知を、検知されたリポジトリ自身に GitHub Issue として自動起票する。

    同名の Open な Issue が既にあればコメントを追記し、無ければ新規作成する。
    GitHub API 呼び出しが失敗しても、CODESCAN 全体の成功を妨げない（DEPSCAN と同じ方針）。

    Args:
        token: 省略時は`settings.GITHUB_TOKEN`（baby-feelings向け毎日クロールの既定）。
            登録済み他ユーザー自身のリポジトリに対して起票する場合（Issue #227）は、
            そのユーザー自身のOAuthアクセストークンを明示的に渡す必要がある。
    """
    _reporter.file_issues(new_snapshots, token)


def close_resolved_repo_issues(
    db: Session, candidate_repos: set[str], token: str | None = None,
) -> None:
    """対応が必要な検知が0件のリポジトリの、Open な CODESCAN Issue をクローズする。

    `candidate_repos` は、全ツールの検査に成功したリポジトリ（失敗したツールがあると、検知が
    減ったのか検査できなかったのか区別できないため、呼び出し側で除く）。

    Args:
        token: 省略時は `settings.GITHUB_TOKEN`（管理者のリポジトリ用）。登録済み他ユーザーの
            リポジトリでは、そのユーザー自身のトークンを渡す。
    """
    _reporter.close_resolved(db, candidate_repos, token)
