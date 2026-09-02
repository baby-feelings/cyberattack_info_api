"""GitHub API クライアントモジュール。

DEPSCAN（依存ライブラリ脆弱性スキャン）機能から、監視対象ユーザーの全リポジトリの
ロックファイルを取得するために使用する。PyGithub 等の SDK は使わず、既存の OSV/JVN
クローラーと同じスタイル（生 httpx）で実装する。
"""
import base64
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_GITHUB_API_BASE = "https://api.github.com"
_TIMEOUT = 30.0
_PER_PAGE = 100


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def list_target_repos(username: str, token: str) -> list[dict[str, Any]]:
    """指定ユーザーが所有する全リポジトリを取得する（fork・archived は除外）。

    `GET /users/{username}/repos` は公開リポジトリしか返さない仕様のため、
    プライベートリポジトリも対象に含めるには認証ユーザー自身の視点で全リポジトリを
    返す `GET /user/repos`（`affiliation=owner`）を使う必要がある。

    Args:
        username: GitHub ユーザー名（トークンの持ち主と一致している前提）
        token: GitHub PAT（Contents: Read-only 推奨）

    Returns:
        リポジトリ情報の辞書リスト（"full_name"・"default_branch" 等を含む）
    """
    repos: list[dict[str, Any]] = []
    page = 1
    with httpx.Client(timeout=_TIMEOUT, headers=_headers(token)) as client:
        while True:
            resp = client.get(
                f"{_GITHUB_API_BASE}/user/repos",
                params={
                    "affiliation": "owner",
                    "per_page": _PER_PAGE,
                    "page": page,
                },
            )
            resp.raise_for_status()
            batch = resp.json()
            if not batch:
                break
            repos.extend(batch)
            if len(batch) < _PER_PAGE:
                break
            page += 1

    return [repo for repo in repos if not repo.get("fork") and not repo.get("archived")]


def get_repo_tree(owner: str, repo: str, default_branch: str, token: str) -> list[str]:
    """リポジトリの全ファイルパス一覧を取得する（サブディレクトリを含む再帰取得）。

    Args:
        owner: リポジトリオーナー
        repo: リポジトリ名
        default_branch: デフォルトブランチ名
        token: GitHub PAT

    Returns:
        ファイルパスのリスト（ディレクトリは除外）
    """
    with httpx.Client(timeout=_TIMEOUT, headers=_headers(token)) as client:
        resp = client.get(
            f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/git/trees/{default_branch}",
            params={"recursive": "1"},
        )
        resp.raise_for_status()
    data = resp.json()

    # GitHub API は巨大なツリーの場合 truncated=true を返す（大規模リポジトリのみ発生）
    if data.get("truncated"):
        logger.warning("Tree truncated for %s/%s: some files may be missed", owner, repo)

    return [
        item["path"]
        for item in data.get("tree", [])
        if item.get("type") == "blob"
    ]


def get_file_content(owner: str, repo: str, path: str, token: str) -> str:
    """リポジトリ内のファイル内容を取得する（GitHub Contents API、base64 デコード済み）。

    Args:
        owner: リポジトリオーナー
        repo: リポジトリ名
        path: ファイルパス
        token: GitHub PAT

    Returns:
        ファイル内容（UTF-8 文字列）
    """
    with httpx.Client(timeout=_TIMEOUT, headers=_headers(token)) as client:
        resp = client.get(f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{path}")
        resp.raise_for_status()
    data = resp.json()
    content = data.get("content", "")
    encoding = data.get("encoding", "base64")
    if encoding != "base64":
        raise ValueError(f"Unsupported content encoding: {encoding}")
    return base64.b64decode(content).decode("utf-8", errors="replace")


def find_open_issue(owner: str, repo: str, title: str, token: str) -> int | None:
    """指定タイトルと完全一致する Open な Issue を検索する（Pull Request は除外）。

    Args:
        owner: リポジトリオーナー
        repo: リポジトリ名
        title: 完全一致で検索する Issue タイトル
        token: GitHub PAT（Issues: Write 権限が必要）

    Returns:
        見つかった Issue 番号。無ければ None。
    """
    with httpx.Client(timeout=_TIMEOUT, headers=_headers(token)) as client:
        resp = client.get(
            f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/issues",
            params={"state": "open", "per_page": _PER_PAGE},
        )
        resp.raise_for_status()
    for issue in resp.json():
        if issue.get("title") == title and "pull_request" not in issue:
            return int(issue["number"])
    return None


def create_issue(owner: str, repo: str, title: str, body: str, token: str) -> dict[str, Any]:
    """Issue を新規作成する。"""
    with httpx.Client(timeout=_TIMEOUT, headers=_headers(token)) as client:
        resp = client.post(
            f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/issues",
            json={"title": title, "body": body},
        )
        resp.raise_for_status()
    return dict(resp.json())


def add_issue_comment(
    owner: str, repo: str, issue_number: int, body: str, token: str,
) -> dict[str, Any]:
    """既存の Issue にコメントを追加する。"""
    with httpx.Client(timeout=_TIMEOUT, headers=_headers(token)) as client:
        resp = client.post(
            f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/issues/{issue_number}/comments",
            json={"body": body},
        )
        resp.raise_for_status()
    return dict(resp.json())
