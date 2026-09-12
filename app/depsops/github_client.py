"""GitHub API クライアントモジュール（DEPSOPS: Dependabot PR運用の自動化用）。

Dependabot が作成した PR の一覧取得・マージ・リベース依頼コメント投稿、
および対象リポジトリに CI（GitHub Actions ワークフロー）が設定されているかの
判定に使用する。既存の app.depscan.github_client とはドメインが異なるため
（あちらはロックファイル収集、こちらは PR 運用）、実装は分離する。
"""
import logging
from typing import Any

import httpx

from app.core.retry import request_with_retry

logger = logging.getLogger(__name__)

_GITHUB_API_BASE = "https://api.github.com"
_TIMEOUT = 30.0
_PER_PAGE = 100

# Dependabot が作成する PR の author（GitHub App の bot アカウント）
_DEPENDABOT_LOGIN = "dependabot[bot]"


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def list_open_dependabot_prs(owner: str, repo: str, token: str) -> list[dict[str, Any]]:
    """Open な Dependabot 作成 PR の一覧を取得する（number・title を含む）。"""
    with httpx.Client(timeout=_TIMEOUT, headers=_headers(token)) as client:
        resp = request_with_retry(
            lambda: client.get(
                f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/pulls",
                params={"state": "open", "per_page": _PER_PAGE},
            ),
        )
    return [
        pr for pr in resp.json()
        if (pr.get("user") or {}).get("login") == _DEPENDABOT_LOGIN
    ]


def get_pull_request(owner: str, repo: str, number: int, token: str) -> dict[str, Any]:
    """PR 詳細を取得する（`mergeable_state` 判定に使用）。"""
    with httpx.Client(timeout=_TIMEOUT, headers=_headers(token)) as client:
        resp = request_with_retry(
            lambda: client.get(f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/pulls/{number}"),
        )
    return dict(resp.json())


def merge_pull_request(owner: str, repo: str, number: int, token: str) -> dict[str, Any]:
    """PR をマージし、ブランチを削除する。"""
    with httpx.Client(timeout=_TIMEOUT, headers=_headers(token)) as client:
        # PUTでの状態遷移（マージ）は冪等（再試行してもマージ済みエラーが返るのみで
        # 重複マージにはならない）ためリトライ対象とする
        resp = request_with_retry(
            lambda: client.put(
                f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/pulls/{number}/merge",
                json={"merge_method": "merge"},
            ),
        )
        merged = dict(resp.json())
        try:
            branch = get_pull_request(owner, repo, number, token)["head"]["ref"]
            client.delete(f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/git/refs/heads/{branch}")
        except httpx.HTTPError as exc:
            # ブランチ削除失敗はマージ自体の成否に影響させない（Dependabotが後で消すこともある）
            logger.warning("Failed to delete branch after merging %s/%s#%d: %s",
                            owner, repo, number, exc)
    return merged


def request_rebase(owner: str, repo: str, number: int, token: str) -> None:
    """PR に `@dependabot rebase` コメントを投稿し、リベースを依頼する。

    新規リソース作成（POST）のためリトライしない（重複コメント投稿のリスクを
    避けるため。app.depscan.github_client.create_issue と同じ方針）。
    """
    with httpx.Client(timeout=_TIMEOUT, headers=_headers(token)) as client:
        resp = client.post(
            f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/issues/{number}/comments",
            json={"body": "@dependabot rebase"},
        )
        resp.raise_for_status()


def has_ci_workflows(owner: str, repo: str, token: str) -> bool:
    """`.github/workflows` 配下に何らかのワークフローファイルがあるか判定する。"""
    with httpx.Client(timeout=_TIMEOUT, headers=_headers(token)) as client:
        try:
            resp = request_with_retry(
                lambda: client.get(
                    f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/contents/.github/workflows",
                ),
            )
        except httpx.HTTPStatusError as exc:
            # 404（workflowsディレクトリが無い）は正常系のため、リトライ対象外・
            # エラーとせずFalseを返す
            if exc.response.status_code == 404:
                return False
            raise
    data = resp.json()
    return isinstance(data, list) and len(data) > 0


def list_open_dependabot_alerts(owner: str, repo: str, token: str) -> list[dict[str, Any]]:
    """Open な Dependabot alert 一覧を取得する。

    `GITHUB_TOKEN` に **Dependabot alerts: Read-only** 権限が必要（DEPSCAN/DEPSOPS で
    従来使っていた Contents: Read-only・Issues: Write・Pull requests: Write には
    含まれない別スコープのため、未設定のトークンでは 403 を送出する。呼び出し側で
    捕捉し、判定不能として扱うこと）。
    """
    with httpx.Client(timeout=_TIMEOUT, headers=_headers(token)) as client:
        resp = request_with_retry(
            lambda: client.get(
                f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/dependabot/alerts",
                params={"state": "open", "per_page": _PER_PAGE},
            ),
        )
    return list(resp.json())
