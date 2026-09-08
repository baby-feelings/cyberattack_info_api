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


# 到達可能性解析でソース走査から除外するディレクトリ（ベンダー化・生成物・依存物）
_EXCLUDED_DIR_SEGMENTS = frozenset({
    "node_modules", "vendor", ".git", "dist", "build", "venv", ".venv",
    "__pycache__", "target", "deps", "_build", "packages",
})

# 到達可能性解析で1リポジトリあたり取得するソースファイル数の上限
# （巨大リポジトリでの過剰な API 呼び出し・処理時間を防ぐための安全弁）
_MAX_SOURCE_FILES = 200
# 1ファイルあたりの取得上限サイズ（バイト。生成物・データファイル等の除外用）
_MAX_SOURCE_FILE_SIZE = 300_000


def get_source_files(
    owner: str, repo: str, default_branch: str, token: str, extensions: tuple[str, ...],
) -> dict[str, str]:
    """指定拡張子に一致するソースファイルの内容を取得する（到達可能性解析用）。

    ベンダー化・生成物ディレクトリ（node_modules 等）は除外する。
    1リポジトリあたりのファイル数・サイズには安全弁として上限を設ける。

    Args:
        owner: リポジトリオーナー
        repo: リポジトリ名
        default_branch: デフォルトブランチ名
        token: GitHub PAT
        extensions: 取得対象の拡張子（例: (".py",)）

    Returns:
        {ファイルパス: 内容} の辞書（取得失敗したファイルは含まれない）
    """
    all_paths = get_repo_tree(owner, repo, default_branch, token)
    matched_paths = [
        path for path in all_paths
        if path.endswith(extensions)
        and not any(f"/{seg}/" in f"/{path}" for seg in _EXCLUDED_DIR_SEGMENTS)
    ][:_MAX_SOURCE_FILES]

    files: dict[str, str] = {}
    for path in matched_paths:
        try:
            content = get_file_content(owner, repo, path, token)
        except httpx.HTTPError as exc:
            logger.warning("Failed to fetch source file %s in %s/%s: %s", path, owner, repo, exc)
            continue
        if len(content) <= _MAX_SOURCE_FILE_SIZE:
            files[path] = content
    return files


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


def close_issue(owner: str, repo: str, issue_number: int, token: str) -> dict[str, Any]:
    """Issue をクローズする（state を "closed" に更新）。"""
    with httpx.Client(timeout=_TIMEOUT, headers=_headers(token)) as client:
        resp = client.patch(
            f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/issues/{issue_number}",
            json={"state": "closed"},
        )
        resp.raise_for_status()
    return dict(resp.json())
