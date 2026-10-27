"""GitHub アカウント単位の操作（そのユーザーが所有するリポジトリの一覧）。

リポジトリ1件に対する操作は `app.core.github.repo.GitHubRepo` にある。
"""
import logging
from typing import Any

from app.core.config import settings
from app.core.github.api import GitHubApi

logger = logging.getLogger(__name__)

_TIMEOUT = 30.0
_PER_PAGE = 100


def excluded_repo_names() -> set[str]:
    """`SCAN_EXCLUDE_REPOS`（カンマ区切りの `owner/name`）を、小文字の集合にして返す。"""
    return {e.strip().lower() for e in settings.SCAN_EXCLUDE_REPOS.split(",") if e.strip()}


def is_excluded_repo(full_name: str) -> bool:
    """スキャン対象外に指定されたリポジトリか（大文字小文字は区別しない）。"""
    return full_name.lower() in excluded_repo_names()


def list_target_repos(token: str) -> list[dict[str, Any]]:
    """トークンの持ち主が所有する全リポジトリを取得する（fork・archived・対象外指定は除外）。

    `GET /users/{username}/repos` は公開リポジトリしか返さないため、プライベートリポジトリも
    対象に含めるには、認証ユーザー自身の視点で全リポジトリを返す `GET /user/repos`
    （`affiliation=owner`）を使う必要がある。

    Args:
        token: GitHub PAT（Contents: Read-only 推奨）

    Returns:
        リポジトリ情報の辞書リスト（"full_name"・"default_branch" 等を含む）
    """
    repos: list[dict[str, Any]] = []
    page = 1
    with GitHubApi(token, timeout=_TIMEOUT) as api:
        while True:
            resp = api.get(
                "/user/repos",
                params={"affiliation": "owner", "per_page": _PER_PAGE, "page": page},
            )
            batch = resp.json()
            if not batch:
                break
            repos.extend(batch)
            if len(batch) < _PER_PAGE:
                break
            page += 1

    excluded = excluded_repo_names()
    return [
        repo for repo in repos
        if not repo.get("fork") and not repo.get("archived")
        and str(repo.get("full_name", "")).lower() not in excluded
    ]
