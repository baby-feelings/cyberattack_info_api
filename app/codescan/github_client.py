"""CODESCAN 専用の GitHub API クライアント。

DEPSCAN の `app.depscan.github_client` はファイル単位（Contents API）で
ロックファイルのみを取得するが、CODESCAN はリポジトリ全体のソースコードを
Semgrep でスキャンする必要があるため、多数の API 呼び出しを要するファイル単位
取得は非効率。代わりに GitHub の tarball 取得エンドポイント
（`GET /repos/{owner}/{repo}/tarball/{ref}`）でリポジトリ全体を1回の
HTTP 呼び出しで取得する。

対象リポジトリ一覧の取得（`list_target_repos` 相当）は DEPSCAN と完全に同じ
対象（GITHUB_USERNAME 配下、fork・archived除外）のため、重複実装せず
`app.depscan.github_client.list_target_repos` をそのまま再利用する（DRY原則）。
"""
import logging

import httpx

from app.core.retry import request_with_retry

logger = logging.getLogger(__name__)

_GITHUB_API_BASE = "https://api.github.com"
# tarball はリポジトリ全体のダウンロードのため、ロックファイル取得等より長めに確保する
_TIMEOUT = 60.0


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def download_repo_tarball(owner: str, repo: str, token: str, branch: str = "HEAD") -> bytes:
    """リポジトリ全体を tarball（.tar.gz）としてバイト列で取得する。

    GitHub の tarball エンドポイントは 302 リダイレクト経由で実データを返すため、
    httpx のデフォルトのリダイレクト非追従設定を明示的に上書きする必要がある。

    Args:
        owner: リポジトリオーナー
        repo: リポジトリ名
        token: GitHub PAT（Contents: Read-only で取得可能）
        branch: 取得対象のブランチ・タグ・コミットSHA（既定 "HEAD" = デフォルトブランチ）

    Returns:
        tar.gz のバイト列（呼び出し側で `tarfile` を使って展開する）
    """
    with httpx.Client(
        timeout=_TIMEOUT, headers=_headers(token), follow_redirects=True,
    ) as client:
        resp = request_with_retry(
            lambda: client.get(
                f"{_GITHUB_API_BASE}/repos/{owner}/{repo}/tarball/{branch}",
            ),
        )
    return resp.content
