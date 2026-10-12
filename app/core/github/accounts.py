"""GitHub アカウント単位の操作（そのユーザーが所有するリポジトリの一覧）。

リポジトリ1件に対する操作は `app.core.github.repo.GitHubRepo` にある。
"""
import logging
from typing import Any

from app.core.github.api import GitHubApi

logger = logging.getLogger(__name__)

_TIMEOUT = 30.0
_PER_PAGE = 100


def list_target_repos(username: str, token: str) -> list[dict[str, Any]]:
    """トークンの持ち主が所有する全リポジトリを取得する（fork・archived は除外）。

    `GET /users/{username}/repos` は公開リポジトリしか返さないため、プライベートリポジトリも
    対象に含めるには、認証ユーザー自身の視点で全リポジトリを返す `GET /user/repos`
    （`affiliation=owner`）を使う必要がある。

    Args:
        username: GitHub ユーザー名（トークンの持ち主と一致している前提。ログ・呼び出し側の
            意図を明示するための引数で、API の絞り込みには使わない）
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

    return [repo for repo in repos if not repo.get("fork") and not repo.get("archived")]
