"""DEPSOPS（Dependabot PR 運用の自動化）が使う GitHub 操作。

Dependabot が作成した PR の一覧取得・マージ・リベース依頼コメント投稿、対象リポジトリに CI
（GitHub Actions ワークフロー）があるかの判定、Dependabot alert の取得を行う。これらは DEPSOPS
固有の判断を含むため、ドメイン共通の `GitHubRepo`（`app.core.github.repo`）には含めず、ここで
`GitHubRepo` の `api()` / `path()` を使って組み立てる。
"""
import logging
from http import HTTPStatus
from typing import Any

import httpx

from app.core.github.repo import GitHubRepo

logger = logging.getLogger(__name__)

_PER_PAGE = 100

# Dependabot が作成する PR の author（GitHub App の bot アカウント）
_DEPENDABOT_LOGIN = "dependabot[bot]"


def list_open_dependabot_prs(repo: GitHubRepo) -> list[dict[str, Any]]:
    """Open な Dependabot 作成 PR の一覧を取得する（number・title を含む）。"""
    with repo.api() as api:
        resp = api.get(repo.path("/pulls"), params={"state": "open", "per_page": _PER_PAGE})
    return [
        pr for pr in resp.json()
        if (pr.get("user") or {}).get("login") == _DEPENDABOT_LOGIN
    ]


def get_pull_request(repo: GitHubRepo, number: int) -> dict[str, Any]:
    """PR 詳細を取得する（`mergeable_state` 判定に使用）。"""
    with repo.api() as api:
        resp = api.get(repo.path(f"/pulls/{number}"))
    return dict(resp.json())


def merge_pull_request(repo: GitHubRepo, number: int) -> dict[str, Any]:
    """PR をマージし、ブランチを削除する。"""
    with repo.api() as api:
        # PUTでの状態遷移（マージ）は冪等（再試行してもマージ済みエラーが返るのみで
        # 重複マージにはならない）ためリトライ対象とする
        resp = api.put(repo.path(f"/pulls/{number}/merge"), json={"merge_method": "merge"})
        merged = dict(resp.json())
        try:
            branch = get_pull_request(repo, number)["head"]["ref"]
            api.delete(repo.path(f"/git/refs/heads/{branch}"))
        except httpx.HTTPError as exc:
            # ブランチ削除失敗はマージ自体の成否に影響させない（Dependabotが後で消すこともある）
            logger.warning("Failed to delete branch after merging %s#%d: %s",
                           repo.full_name, number, exc)
    return merged


def request_rebase(repo: GitHubRepo, number: int) -> None:
    """PR に `@dependabot rebase` コメントを投稿し、リベースを依頼する。

    新規リソース作成（POST）のためリトライしない（重複コメント投稿のリスクを避けるため。
    `GitHubRepo.create_issue` と同じ方針）。
    """
    with repo.api() as api:
        api.post(repo.path(f"/issues/{number}/comments"), json={"body": "@dependabot rebase"})


def has_ci_workflows(repo: GitHubRepo) -> bool:
    """`.github/workflows` 配下に何らかのワークフローファイルがあるか判定する。"""
    with repo.api() as api:
        try:
            resp = api.get(repo.path("/contents/.github/workflows"))
        except httpx.HTTPStatusError as exc:
            # 404（workflowsディレクトリが無い）は正常系のため、リトライ対象外・
            # エラーとせずFalseを返す
            if exc.response.status_code == HTTPStatus.NOT_FOUND:
                return False
            raise
    data = resp.json()
    return isinstance(data, list) and len(data) > 0


def list_open_dependabot_alerts(repo: GitHubRepo) -> list[dict[str, Any]]:
    """Open な Dependabot alert 一覧を取得する。

    `GITHUB_TOKEN` に **Dependabot alerts: Read-only** 権限が必要（DEPSCAN/DEPSOPS で
    従来使っていた Contents: Read-only・Issues: Write・Pull requests: Write には
    含まれない別スコープのため、未設定のトークンでは 403 を送出する。呼び出し側で
    捕捉し、判定不能として扱うこと）。
    """
    with repo.api() as api:
        resp = api.get(
            repo.path("/dependabot/alerts"), params={"state": "open", "per_page": _PER_PAGE},
        )
    return list(resp.json())
