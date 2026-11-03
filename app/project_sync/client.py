"""GitHub Projects (v2) への項目の追加に使う、GraphQL・REST の呼び出し（PROJSYNC）。

Project は GraphQL でしか操作できない。Project への項目の追加は、Issue・PR の「ノード ID」
（REST の応答の `node_id`）を使う。トークンに `project` 権限が無いと、GraphQL は 200 のまま
`INSUFFICIENT_SCOPES` のエラーを返すため、`ProjectScopeError` として呼び出し側に伝える
（権限不足を、0 件の同期と見なさないため）。

トークンの値は、ログ・例外のメッセージに含めない。
"""
import logging
from typing import Any

from app.core.github.api import MAX_PER_PAGE, GitHubApi
from app.core.github.repo import GitHubRepo

logger = logging.getLogger(__name__)

# 安全弁: Project の項目・リポジトリの Issue/PR を読むページ数の上限（過剰な API 呼び出しを防ぐ）
_MAX_PROJECT_PAGES = 50
_MAX_REPO_PAGES = 20

_ITEMS_QUERY = """
query($login: String!, $number: Int!, $cursor: String) {
  user(login: $login) {
    projectV2(number: $number) {
      id
      items(first: 100, after: $cursor) {
        pageInfo { hasNextPage endCursor }
        nodes { content { ... on Issue { id } ... on PullRequest { id } } }
      }
    }
  }
}
"""

_ADD_MUTATION = """
mutation($project: ID!, $content: ID!) {
  addProjectV2ItemById(input: {projectId: $project, contentId: $content}) { item { id } }
}
"""


class ProjectSyncError(Exception):
    """GraphQL がエラーを返した（権限不足以外）。"""


class ProjectScopeError(ProjectSyncError):
    """トークンに `project` 権限が無い（GitHub で、トークンに `project` 権限を足す必要がある）。"""


def graphql(api: GitHubApi, query: str, variables: dict[str, Any]) -> dict[str, Any]:
    """GraphQL を1回呼び、`data` を返す。エラー応答は例外にする（HTTP エラーは `httpx` の例外）。"""
    body = api.post("/graphql", json={"query": query, "variables": variables}).json()
    errors = body.get("errors")
    if errors:
        if any(e.get("type") == "INSUFFICIENT_SCOPES" for e in errors):
            raise ProjectScopeError("GITHUB_TOKEN に `project` 権限がありません")
        messages = "; ".join(str(e.get("message", "")) for e in errors)[:300]
        raise ProjectSyncError(f"GraphQL error: {messages}")
    data: dict[str, Any] = body.get("data") or {}
    return data


def fetch_project(api: GitHubApi, login: str, number: int) -> tuple[str, set[str]]:
    """Project の ID と、すでに載っている Issue・PR のノード ID の集合を返す。"""
    project_id = ""
    existing: set[str] = set()
    cursor: str | None = None
    for _ in range(_MAX_PROJECT_PAGES):
        data = graphql(api, _ITEMS_QUERY, {"login": login, "number": number, "cursor": cursor})
        project = (data.get("user") or {}).get("projectV2")
        if not project:
            raise ProjectSyncError(f"Project #{number} が見つかりません（{login}）")
        project_id = project["id"]
        items = project["items"]
        for node in items["nodes"]:
            content = (node or {}).get("content") or {}
            if content.get("id"):
                existing.add(content["id"])
        if not items["pageInfo"]["hasNextPage"]:
            break
        cursor = items["pageInfo"]["endCursor"]
    return project_id, existing


def list_open_items(repo: GitHubRepo) -> list[dict[str, str]]:
    """リポジトリの Open の Issue・PR（`node_id`・`html_url`）を返す。

    `GET /repos/{r}/issues` は、PR も含めて返す（PR には `pull_request` キーが付く）。
    """
    items: list[dict[str, str]] = []
    with repo.api() as api:
        for page in range(1, _MAX_REPO_PAGES + 1):
            resp = api.get(
                repo.path("/issues"),
                params={"state": "open", "per_page": MAX_PER_PAGE, "page": page},
            )
            resp.raise_for_status()
            batch = resp.json()
            items.extend({"node_id": i["node_id"], "html_url": i["html_url"]} for i in batch)
            if len(batch) < MAX_PER_PAGE:
                break
    return items


def add_item(api: GitHubApi, project_id: str, content_id: str) -> None:
    """Issue・PR を Project に追加する（すでに載っていても、エラーにならない）。"""
    graphql(api, _ADD_MUTATION, {"project": project_id, "content": content_id})
