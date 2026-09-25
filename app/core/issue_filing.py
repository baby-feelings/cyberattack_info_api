"""検知結果を対象リポジトリ自身の GitHub Issue へ自動起票する共通処理。

DEPSCAN（`app.depscan.issue_management`）と CODESCAN（`app.codescan.issue_management`）は
「新規検知をリポジトリ単位でグルーピングし、同名の Open Issue があればコメント追記、
無ければ新規作成する」という同一の手順を踏むが、Issueタイトル・本文の整形方法・
ログ接頭辞（"DEPSCAN"/"CODESCAN"）のみが異なる。この共通の手順のみをここに切り出し、
各ドメイン固有の差分（タイトル・本文フォーマッタ）は呼び出し側から渡させる
（DRY原則。Issueクローズ判定はDEPSCAN専用のため対象外 — 両ドメインのdocstring参照）。
"""
import logging
from collections.abc import Callable
from typing import Any

import httpx

from app.depscan.github_client import add_issue_comment, create_issue, find_open_issue

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
        owner, repo = full_name.split("/", 1)
        body = format_body(findings)
        try:
            issue_number = find_open_issue(owner, repo, issue_title, token)
            if issue_number is not None:
                add_issue_comment(owner, repo, issue_number, body, token)
                logger.info(
                    "%s: added comment to existing issue #%d in %s",
                    log_prefix, issue_number, full_name,
                )
            else:
                issue = create_issue(owner, repo, issue_title, body, token)
                logger.info(
                    "%s: created issue #%s in %s", log_prefix, issue.get("number"), full_name,
                )
        except httpx.HTTPError as exc:
            logger.warning(
                "%s: failed to file GitHub issue for %s: %s", log_prefix, full_name, exc,
            )
