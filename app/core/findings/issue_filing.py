"""検知結果を対象リポジトリ自身の GitHub Issue へ自動起票する共通処理。

DEPSCAN（`app.depscan.issue_management`）と CODESCAN（`app.codescan.issue_management`）は
「新規検知をリポジトリ単位でグルーピングし、同名の Open Issue があればコメント追記、
無ければ新規作成する」という同一の手順を踏むが、Issueタイトル・本文の整形方法・
ログ接頭辞（"DEPSCAN"/"CODESCAN"）のみが異なる。この共通の手順のみをここに切り出し、
各ドメイン固有の差分（タイトル・本文フォーマッタ）は呼び出し側から渡させる
（DRY原則）。

起票とクローズの両方を持つドメイン（DEPSCAN・CODESCAN）は、`IssueReporter` を継承して、
差分（タイトル・本文・未解決の数え方）だけを実装する（Template Method）。
"""
import logging
from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db_utils import now_utc
from app.core.github.repo import GitHubRepo

logger = logging.getLogger(__name__)


def file_or_update_repo_issues(
    new_snapshots: list[dict[str, Any]],
    issue_title: str,
    format_body: Callable[[list[dict[str, Any]]], str],
    token: str,
    log_prefix: str,
) -> None:
    """新規検知を、検知されたリポジトリ自身に GitHub Issue として自動起票する。

    同名の Open な Issue が既にあればコメントを追記し、無ければ新規作成する。
    GitHub API 呼び出しが失敗しても（Issues 書き込み権限が無いトークン等）、
    呼び出し元のクロール全体の成功を妨げないようリポジトリ単位で例外を握りつぶす。

    Args:
        new_snapshots: 新規挿入された finding のスナップショット辞書のリスト
            （各要素は最低限 `repo_full_name` キーを持つこと）。
        issue_title: Issue自動起票時のタイトル（Open Issue検索の一致キーも兼ねる）。
        format_body: 1リポジトリ分の finding リストを受け取り、Issue本文（Markdown）
            を組み立てるコールバック（ドメインごとの表示フォーマットの差分はここに集約する）。
        token: Issue作成に使うGitHub PAT・OAuthアクセストークン。
        log_prefix: ログメッセージの接頭辞（"DEPSCAN"・"CODESCAN"等）。
    """
    if not new_snapshots:
        return

    by_repo: dict[str, list[dict[str, Any]]] = {}
    for finding in new_snapshots:
        by_repo.setdefault(finding["repo_full_name"], []).append(finding)

    for full_name, findings in by_repo.items():
        repo = GitHubRepo.from_full_name(full_name, token)
        body = format_body(findings)
        try:
            issue_number = repo.find_open_issue(issue_title)
            if issue_number is not None:
                repo.add_issue_comment(issue_number, body)
                logger.info(
                    "%s: added comment to existing issue #%d in %s",
                    log_prefix, issue_number, full_name,
                )
            else:
                issue = repo.create_issue(issue_title, body)
                logger.info(
                    "%s: created issue #%s in %s", log_prefix, issue.get("number"), full_name,
                )
        except httpx.HTTPError as exc:
            logger.warning(
                "%s: failed to file GitHub issue for %s: %s", log_prefix, full_name, exc,
            )


class IssueReporter(ABC):
    """検知結果の GitHub Issue の「起票」と「自動クローズ」の共通の手順（Template Method）。

    ドメインごとの差分は、クラス属性（`source`・`issue_title`・`resolved_subject`）と、
    抽象メソッド（`format_body`・`unresolved_count`）だけ。GitHub API の失敗は、リポジトリ単位で
    握りつぶし、呼び出し元のスキャン全体を失敗させない。
    """

    # ログの接頭辞（"DEPSCAN"・"CODESCAN" など）
    source: str
    # 起票時のタイトル（Open Issue 検索の一致キーも兼ねる。他のドメインの Issue と混同しない文字列）
    issue_title: str
    # クローズ時のコメントに入れる対象の名前（例: "依存ライブラリ脆弱性"）
    resolved_subject: str

    @abstractmethod
    def format_body(self, findings: list[dict[str, Any]], timestamp: str) -> str:
        """1リポジトリ分の検知（スナップショット）から、Issue 本文（Markdown）を組み立てる。"""

    @abstractmethod
    def unresolved_count(self, db: Session, full_name: str) -> int:
        """リポジトリに残る「対応が必要な検知」の数（受容などの例外は数えない）。"""

    def file_issues(self, new_snapshots: list[dict[str, Any]], token: str | None = None) -> None:
        """新規検知を、検知されたリポジトリ自身に Issue として起票（既存があれば追記）する。

        Args:
            token: 省略時は `settings.GITHUB_TOKEN`（管理者のリポジトリ向け）。登録済み他ユーザーの
                リポジトリでは、そのユーザー自身の OAuth トークンを渡す（`GITHUB_TOKEN` には
                他ユーザーのプライベートリポジトリへの書き込み権限が無いため）。
        """
        if not new_snapshots:
            return

        timestamp = now_utc().strftime("%Y-%m-%d %H:%M UTC")
        token = token if token is not None else settings.GITHUB_TOKEN
        file_or_update_repo_issues(
            new_snapshots,
            self.issue_title,
            lambda findings: self.format_body(findings, timestamp),
            token,
            self.source,
        )

    def close_resolved(
        self, db: Session, candidate_repos: set[str], token: str | None = None,
    ) -> None:
        """対応が必要な検知が0件になったリポジトリの、Open な Issue をクローズする。

        Issue 本文の個々の検知ではなく、「そのリポジトリに、対応が必要な検知が残っているか」で
        判定する（シンプルな設計判断）。`candidate_repos` に絞ることで、無関係なリポジトリへの
        無駄な API 呼び出しを避ける。Open な Issue が無いリポジトリは、何もしない。

        Args:
            token: 省略時は `settings.GITHUB_TOKEN`。
        """
        if not candidate_repos:
            return

        token = token if token is not None else settings.GITHUB_TOKEN
        timestamp = now_utc().strftime("%Y-%m-%d %H:%M UTC")

        for full_name in sorted(candidate_repos):
            if self.unresolved_count(db, full_name) > 0:
                continue

            repo = GitHubRepo.from_full_name(full_name, token)
            try:
                issue_number = repo.find_open_issue(self.issue_title)
                if issue_number is None:
                    continue
                repo.add_issue_comment(
                    issue_number,
                    f"対応が必要な{self.resolved_subject}（受容などの例外を除く）が0件になったため"
                    f"自動的にクローズします（{timestamp}）。",
                )
                repo.close_issue(issue_number)
                logger.info(
                    "%s: closed issue #%d in %s (0 unresolved findings)",
                    self.source, issue_number, full_name,
                )
            except httpx.HTTPError as exc:
                logger.warning(
                    "%s: failed to close GitHub issue for %s: %s", self.source, full_name, exc,
                )
