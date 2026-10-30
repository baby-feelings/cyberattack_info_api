"""リポジトリの設定の収集（GitHub API。判定は `checks`）。

取得できなかった項目は、`None`（取得不可）で返し、「設定が無い」（空・False）と区別する。
権限不足・機能が使えないプランは、403・404 になる。それ以外の失敗（5xx・通信）は、例外で伝える。
"""
import logging
from collections.abc import Callable
from typing import Any

from app.core.github.api import GitHubApi
from app.core.github.repo import GitHubRepo
from app.repo_audit.checks import hook_url, sanitize_url

logger = logging.getLogger(__name__)

_PER_PAGE = 100
# 非公開の無料リポジトリで、ブランチ保護の取得が 403 になるときの、応答の文言
_UPGRADE_HINT = "upgrade"


def _optional_get(api: GitHubApi, path: str, **params: Any) -> tuple[int, Any]:
    """GET して (ステータス, JSON) を返す。403・404 は例外にせず、そのまま返す。"""
    response = api.get(path, params=params or None)
    if response.status_code in (403, 404):
        try:
            return response.status_code, response.json()
        except ValueError:
            return response.status_code, {}
    response.raise_for_status()
    body: Any = response.json() if response.content else None
    return response.status_code, body


def _list_or_none(api: GitHubApi, path: str) -> list[dict[str, Any]] | None:
    status, body = _optional_get(api, path, per_page=_PER_PAGE)
    return None if status in (403, 404) else list(body or [])


def _branch_protection(api: GitHubApi, repo: GitHubRepo, branch: str) -> Any:
    """既定ブランチの保護。設定の辞書・False（未保護）・"not_enforceable"（設定できない）・None（取得不可）。"""
    status, body = _optional_get(api, repo.path(f"/branches/{branch}/protection"))
    if status == 404:
        # 「保護されていない」と「リポジトリが見えない」は、メッセージで区別する
        message = str((body or {}).get("message", "")).lower()
        return False if "not protected" in message else None
    if status == 403:
        message = str((body or {}).get("message", "")).lower()
        return "not_enforceable" if _UPGRADE_HINT in message else None
    return dict(body or {})


def collect(repo: GitHubRepo, default_branch: str) -> dict[str, Any]:
    """1リポジトリの設定を集める。"""
    with repo.api() as api:
        status, info = _optional_get(api, repo.path(""))
        repo_info = None if status in (403, 404) else dict(info)
        # Dependabot alerts: 204=有効・404=無効（リポジトリが見えない場合と、区別できない）
        alerts_status, _ = _optional_get(api, repo.path("/vulnerability-alerts"))
        vulnerability_alerts: bool | None
        if alerts_status == 403:
            vulnerability_alerts = None
        else:
            vulnerability_alerts = alerts_status != 404
        collaborators = _list_or_none(api, repo.path("/collaborators?affiliation=direct"))
        return {
            "repo": repo_info,
            "vulnerability_alerts": vulnerability_alerts,
            "branch_protection": _branch_protection(api, repo, default_branch),
            "keys": _list_or_none(api, repo.path("/keys")),
            "hooks": _list_or_none(api, repo.path("/hooks")),
            "collaborators": collaborators,
        }


def snapshot_of(raw: dict[str, Any]) -> dict[str, list[str] | None]:
    """デプロイキー・Webhook・共同編集者の、識別子の一覧（変化の検知用。取得不可は None）。

    名前（タイトル）だけでは、同名のキーの差し替えや、権限の変更（読み取り→書き込み）を見逃すため、
    一意な ID と権限を含める。Webhook の URL は、認証情報・クエリを除いて持つ。
    """

    def identities(
        items: list[dict[str, Any]] | None, make: Callable[[dict[str, Any]], str],
    ) -> list[str] | None:
        return None if items is None else sorted(make(i) for i in items)

    return {
        "keys": identities(
            raw.get("keys"),
            lambda k: (
                f"{k.get('id')}:{k.get('title')}:{'ro' if k.get('read_only', True) else 'rw'}"
            ),
        ),
        "hooks": identities(
            raw.get("hooks"), lambda h: f"{h.get('id')}:{sanitize_url(hook_url(h))}",
        ),
        "collaborators": identities(
            raw.get("collaborators"),
            lambda c: f"{c.get('login')}:{c.get('role_name') or 'unknown'}",
        ),
    }
