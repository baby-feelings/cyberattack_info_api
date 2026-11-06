"""DEPSCAN 検知結果の GitHub Issue 管理（起票・追記・自動クローズ）。

起票・クローズの共通の手順は `app.core.issue_filing.IssueReporter`（Template Method）にあり、
ここには DEPSCAN 固有の差分（タイトル・本文・未解決の数え方）だけを置く。
DEPSCAN 全体のオーケストレーション（crawler.py）とは責務を分離する。

公開する関数（`file_github_issues`・`close_resolved_repo_issues`）は、呼び出し元
（crawler・user_scan・例外の同期）が変わらないよう、`DepscanIssueReporter` への委譲にしている。
"""
from typing import Any

from sqlalchemy.orm import Session

from app.core.finding_format import format_malicious_section, format_package_lines, split_malicious
from app.core.issue_filing import IssueReporter
from app.core.notifications.slack import DASHBOARD_URL
from app.depscan.models import DependencyFinding
from app.finding_exceptions.matching import not_excepted
from app.finding_exceptions.models import KIND_DEPENDENCY

# GitHub Issue自動起票時のタイトル（Open Issue検索の一致キーも兼ねる）
ISSUE_TITLE = "🚨 依存ライブラリの脆弱性が検出されました (DEPSCAN)"


class DepscanIssueReporter(IssueReporter):
    """DEPSCAN（依存ライブラリの脆弱性）の Issue の起票とクローズ。"""

    source = "DEPSCAN"
    issue_title = ISSUE_TITLE
    resolved_subject = "依存ライブラリ脆弱性"

    def format_body(self, findings: list[dict[str, Any]], timestamp: str) -> str:
        malicious, others = split_malicious(findings)
        # 悪意あるパッケージは、脆弱性の一覧より前に、対応手順つきで示す
        malicious_section = (
            "\n".join(format_malicious_section(malicious)) + "\n\n" if malicious else ""
        )
        return (
            f"DEPSCAN が依存ライブラリの脆弱性を検知しました（{timestamp}）。\n\n"
            + malicious_section
            + "\n".join(format_package_lines(others))
            + f"\n\n---\n詳細: {DASHBOARD_URL}"
        )

    def unresolved_count(self, db: Session, full_name: str) -> int:
        # 例外（受容など）にした検知は、対応が要らないため、残りに数えない（Issue #403）
        return not_excepted(
            db.query(DependencyFinding).filter(
                DependencyFinding.repo_full_name == full_name,
                DependencyFinding.resolved_at.is_(None),
            ),
            KIND_DEPENDENCY,
        ).count()


_reporter = DepscanIssueReporter()


def file_github_issues(new_snapshots: list[dict[str, Any]], token: str | None = None) -> None:
    """新規検知を、検知されたリポジトリ自身に GitHub Issue として自動起票する。

    同名の Open な Issue が既にあればコメントを追記し、無ければ新規作成する。
    GitHub API 呼び出しが失敗しても、DEPSCAN 全体の成功を妨げない。

    Args:
        token: 省略時は`settings.GITHUB_TOKEN`（baby-feelings向け毎日クロールの
            既定）。登録済み他ユーザー自身のリポジトリに対して起票する場合
            （Issue #227）は、そのユーザー自身のOAuthアクセストークンを渡す。
    """
    _reporter.file_issues(new_snapshots, token)


def close_resolved_repo_issues(
    db: Session, candidate_repos: set[str], token: str | None = None,
) -> None:
    """未解決 finding が0件になったリポジトリの Open な DEPSCAN Issue をクローズする。

    `candidate_repos`（今回のスキャンで1件以上 finding が解決したリポジトリ）に絞って
    チェックする。GitHub API の失敗は、リポジトリ単位で握りつぶす（起票と同じ方針）。
    """
    _reporter.close_resolved(db, candidate_repos, token)
