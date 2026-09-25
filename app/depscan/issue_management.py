"""DEPSCAN 検知結果の GitHub Issue 管理（起票・追記・自動クローズ）。

app.depscan.crawler から GitHub Issue 関連ロジックのみを切り出したモジュール。
新規検知の起票（`_file_github_issues`）・未解決 finding が0件になった
リポジトリの自動クローズ（`_close_resolved_repo_issues`）を担当し、
DEPSCAN 全体のオーケストレーション（crawler.py）とは責務を分離する。
"""
import logging
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.finding_format import format_package_lines
from app.core.issue_filing import file_or_update_repo_issues
from app.core.notifications import DASHBOARD_URL
from app.crawler_logs.writer import now_utc
from app.depscan.github_client import add_issue_comment, close_issue, find_open_issue
from app.depscan.models import DependencyFinding

logger = logging.getLogger(__name__)

# GitHub Issue自動起票時のタイトル（Open Issue検索の一致キーも兼ねる）
_ISSUE_TITLE = "🚨 依存ライブラリの脆弱性が検出されました (DEPSCAN)"


def _file_github_issues(new_snapshots: list[dict[str, Any]], token: str | None = None) -> None:
    """新規検知を、検知されたリポジトリ自身に GitHub Issue として自動起票する。

    同名の Open な Issue が既にあればコメントを追記し、無ければ新規作成する。
    GitHub API 呼び出しが失敗しても（Issues 書き込み権限が無いトークン等）、
    DEPSCAN 全体の成功を妨げないようリポジトリ単位で例外を握りつぶす。

    Args:
        token: 省略時は`settings.GITHUB_TOKEN`（baby-feelings向け毎日クロールの
            既定）。登録済み他ユーザー自身のリポジトリに対して起票する場合
            （Issue #227）は、そのユーザー自身のOAuthアクセストークンを渡す。
    """
    if not new_snapshots:
        return

    timestamp = now_utc().strftime("%Y-%m-%d %H:%M UTC")
    token = token if token is not None else settings.GITHUB_TOKEN

    def format_body(findings: list[dict[str, Any]]) -> str:
        return (
            f"DEPSCAN が依存ライブラリの脆弱性を検知しました（{timestamp}）。\n\n"
            + "\n".join(format_package_lines(findings))
            + f"\n\n---\n詳細: {DASHBOARD_URL}"
        )

    file_or_update_repo_issues(new_snapshots, _ISSUE_TITLE, format_body, token, "DEPSCAN")


def _close_resolved_repo_issues(db: Session, candidate_repos: set[str]) -> None:
    """未解決 finding が0件になったリポジトリの Open な DEPSCAN Issue をクローズする。

    Issue 本文に列挙された個々の CVE を突き合わせるのではなく、「そのリポジトリに
    今なお未解決の finding が1件でも残っているか」で判定する（シンプルな設計判断）。
    `candidate_repos`（今回のスキャンで1件以上 finding が解決したリポジトリ）に
    絞ってチェックすることで、無関係なリポジトリへの無駄な API 呼び出しを避ける。
    GitHub API 呼び出しが失敗してもリポジトリ単位で握りつぶし、DEPSCAN 全体の
    成功可否には影響させない（Issue 起票と同じ方針）。
    """
    if not candidate_repos:
        return

    token = settings.GITHUB_TOKEN
    timestamp = now_utc().strftime("%Y-%m-%d %H:%M UTC")

    for full_name in candidate_repos:
        remaining = (
            db.query(DependencyFinding)
            .filter(
                DependencyFinding.repo_full_name == full_name,
                DependencyFinding.resolved_at.is_(None),
            )
            .count()
        )
        if remaining > 0:
            continue

        owner, repo = full_name.split("/", 1)
        try:
            issue_number = find_open_issue(owner, repo, _ISSUE_TITLE, token)
            if issue_number is None:
                continue
            add_issue_comment(
                owner, repo, issue_number,
                f"未解決の依存ライブラリ脆弱性が0件になったため自動的にクローズします"
                f"（{timestamp}）。",
                token,
            )
            close_issue(owner, repo, issue_number, token)
            logger.info(
                "DEPSCAN: closed issue #%d in %s (0 unresolved findings)", issue_number, full_name,
            )
        except httpx.HTTPError as exc:
            logger.warning("DEPSCAN: failed to close GitHub issue for %s: %s", full_name, exc)
