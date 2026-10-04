"""GitHub REST API 呼び出しの共通部分（DEPSCAN/CODESCAN/DEPSOPS で共有）。

3つのドメイン（`app.depscan.github_client` / `app.codescan.github_client` /
`app.depsops.github_client`）はそれぞれ異なる目的（ロックファイル収集・
tarball取得・PR運用）で GitHub API を呼ぶため、高レベルの関数群は意図的に
分離している（ドメインごとの責務が異なるため、まとめると低凝集になる）。
ただし認証ヘッダーの組み立てと API ベース URL は3ドメインで完全に同一であり、
コピペで揃え続けるのは事故の元（ヘッダー仕様変更時の修正漏れ）になるため、
ここに一箇所だけ切り出す（DRY原則）。
"""

import logging
from types import TracebackType
from typing import Any

import httpx

from app.core.retry import request_with_retry

logger = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com"


def github_headers(token: str) -> dict[str, str]:
    """GitHub REST API 呼び出し用の認証ヘッダーを組み立てる。"""
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


class GitHubApi:
    """認証済みの GitHub REST API クライアント（1回分の接続とリトライ方針をカプセル化する）。

    3ドメイン（DEPSCAN/CODESCAN/DEPSOPS）の `github_client` が、関数ごとに
    「`httpx.Client` を開く → 認証ヘッダー付与 → `request_with_retry` で呼ぶ」を
    コピペしていたものを、1か所に集約する。`with` ブロック内で複数回の呼び出しを
    同じ接続で行える（ページング等）。

    リトライ方針（呼び出し側が意識しなくてよいようメソッドごとに固定）:
        - get / put / patch: 冪等なためリトライする（一時障害・レート制限のみ）
        - post / delete: 新規作成・削除は重複のリスクがあるためリトライしない
          （post は失敗時に `raise_for_status` する。delete は従来どおり例外にしない）
    """

    def __init__(
        self, token: str, *, timeout: float = 30.0, follow_redirects: bool = False,
    ) -> None:
        self._token = token
        self._timeout = timeout
        self._follow_redirects = follow_redirects
        self._cm: Any = None
        self._client: Any = None

    def __enter__(self) -> "GitHubApi":
        kwargs: dict[str, Any] = {"timeout": self._timeout, "headers": github_headers(self._token)}
        if self._follow_redirects:
            kwargs["follow_redirects"] = True
        self._cm = httpx.Client(**kwargs)
        self._client = self._cm.__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._cm.__exit__(exc_type, exc, tb)

    @staticmethod
    def _url(path: str) -> str:
        return f"{GITHUB_API_BASE}{path}"

    def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return request_with_retry(lambda: self._client.get(self._url(path), **kwargs))

    def put(self, path: str, **kwargs: Any) -> httpx.Response:
        return request_with_retry(lambda: self._client.put(self._url(path), **kwargs))

    def patch(self, path: str, **kwargs: Any) -> httpx.Response:
        return request_with_retry(lambda: self._client.patch(self._url(path), **kwargs))

    def post(self, path: str, **kwargs: Any) -> httpx.Response:
        resp: httpx.Response = self._client.post(self._url(path), **kwargs)
        resp.raise_for_status()
        return resp

    def delete(self, path: str, **kwargs: Any) -> httpx.Response:
        resp: httpx.Response = self._client.delete(self._url(path), **kwargs)
        return resp
