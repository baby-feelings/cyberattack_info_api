"""1つの GitHub リポジトリに対する、ドメイン共通の REST 操作（`GitHubRepo`）。

以前は `(owner, repo, token)` の3点セットを、DEPSCAN・CODESCAN・DEPSOPS の関数群が毎回引数で
受け渡していた（データの塊）。ここでは「どのリポジトリに、誰の権限でアクセスするか」を1つの値
オブジェクトにまとめ、そのリポジトリへの操作をメソッドとして持たせる（Tell, Don't Ask）。

ここに置くのは、複数のドメインが共有する操作（存在確認・ファイル取得・tarball・Issue 操作）だけ。
DEPSOPS の PR 操作のようにドメイン固有の判断を含むものは各ドメインに残し、`GitHubRepo` の
`api()` / `path()` を使って組み立てる（共通部分は `GitHubRepo`、固有部分はドメイン、の分担）。
"""
import base64
import logging
from dataclasses import dataclass, field
from http import HTTPStatus
from typing import Any

import httpx

from app.core.github.api import GitHubApi

logger = logging.getLogger(__name__)

_TIMEOUT = 30.0
# tarball はリポジトリ全体のダウンロードのため、他の呼び出しより長めに確保する
_TARBALL_TIMEOUT = 60.0
_PER_PAGE = 100


@dataclass(frozen=True)
class GitHubRepo:
    """GitHub 上の1リポジトリと、アクセスに使うトークン。

    token は repr に出さない（ログや例外メッセージへの混入を防ぐ）。
    """

    owner: str
    name: str
    token: str = field(repr=False)

    @classmethod
    def from_full_name(cls, full_name: str, token: str) -> "GitHubRepo":
        """`owner/name` 形式の名前から作る。"""
        owner, _, name = full_name.partition("/")
        return cls(owner, name, token)

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"

    # ── ドメイン固有の操作を組み立てるための部品 ──

    def api(self, *, timeout: float = _TIMEOUT, follow_redirects: bool = False) -> GitHubApi:
        """このリポジトリのトークンで認証された API クライアント（`with` で使う）。"""
        return GitHubApi(self.token, timeout=timeout, follow_redirects=follow_redirects)

    def path(self, suffix: str = "") -> str:
        """このリポジトリ配下の API パス（`path("/pulls")` → `/repos/{owner}/{name}/pulls`）。"""
        return f"/repos/{self.owner}/{self.name}{suffix}"

    # ── 存在確認・ファイル ──

    def exists(self) -> bool | None:
        """このリポジトリが GitHub 上に実在するかを確認する（Issue #228）。

        一覧（`list_target_repos`）から消えたリポジトリが、本当に削除されたのか（DB データを
        パージしてよい）、一時的な API 障害・アーカイブ化・権限変更で外れているだけなのか
        （パージすべきでない）を区別するために使う。

        Returns:
            True: 存在する。False: 404（削除された、またはリネームで到達不能）。
            None: 判定不能（一時的なエラー・レート制限等）。呼び出し元は安全側に倒し、判定不能な間は
            DB データを削除しないこと。
        """
        try:
            with self.api() as api:
                api.get(self.path())
            return True
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == HTTPStatus.NOT_FOUND:
                return False
            logger.warning("exists: unexpected status for %s: %s", self.full_name, exc)
            return None
        except httpx.HTTPError as exc:
            logger.warning("exists: failed to check %s: %s", self.full_name, exc)
            return None

    def tree(self, branch: str) -> list[str]:
        """全ファイルのパス一覧を取得する（サブディレクトリを含む再帰取得。ディレクトリは除外）。"""
        with self.api() as api:
            resp = api.get(self.path(f"/git/trees/{branch}"), params={"recursive": "1"})
        data = resp.json()
        # 巨大なツリーでは GitHub が truncated=true を返す（大規模リポジトリのみ）
        if data.get("truncated"):
            logger.warning("Tree truncated for %s: some files may be missed", self.full_name)
        return [item["path"] for item in data.get("tree", []) if item.get("type") == "blob"]

    def file_content(self, path: str) -> str:
        """ファイルの内容を取得する（Contents API。base64 デコード済みの UTF-8 文字列）。"""
        with self.api() as api:
            resp = api.get(self.path(f"/contents/{path}"))
        data = resp.json()
        encoding = data.get("encoding", "base64")
        if encoding != "base64":
            raise ValueError(f"Unsupported content encoding: {encoding}")
        return base64.b64decode(data.get("content", "")).decode("utf-8", errors="replace")

    def tarball(self, ref: str = "HEAD") -> bytes:
        """リポジトリ全体を tar.gz のバイト列で取得する（1回の HTTP 呼び出し。CODESCAN 用）。

        GitHub の tarball エンドポイントは 302 リダイレクト経由で実データを返すため、
        リダイレクトを追従する。ref は ブランチ・タグ・コミット SHA（既定 HEAD = 既定ブランチ）。
        """
        with self.api(timeout=_TARBALL_TIMEOUT, follow_redirects=True) as api:
            resp = api.get(self.path(f"/tarball/{ref}"))
        return resp.content

    # ── Issue ──

    def find_open_issue(self, title: str) -> int | None:
        """指定タイトルと完全一致する Open な Issue の番号を返す（Pull Request は除外）。"""
        with self.api() as api:
            resp = api.get(self.path("/issues"), params={"state": "open", "per_page": _PER_PAGE})
        for issue in resp.json():
            if issue.get("title") == title and "pull_request" not in issue:
                return int(issue["number"])
        return None

    def create_issue(self, title: str, body: str) -> dict[str, Any]:
        """Issue を新規作成する。

        新規作成（POST）はリトライしない（タイムアウトで応答を受け取れなくても実際には作成済みの
        ことがあり、重複作成になるため。冪等な GET やクローズとは方針が異なる）。
        """
        with self.api() as api:
            resp = api.post(self.path("/issues"), json={"title": title, "body": body})
        return dict(resp.json())

    def add_issue_comment(self, number: int, body: str) -> dict[str, Any]:
        """既存の Issue にコメントを追加する（`create_issue` と同じ理由でリトライしない）。"""
        with self.api() as api:
            resp = api.post(self.path(f"/issues/{number}/comments"), json={"body": body})
        return dict(resp.json())

    def close_issue(self, number: int) -> dict[str, Any]:
        """Issue をクローズする。冪等な操作のためリトライする。"""
        with self.api() as api:
            resp = api.patch(self.path(f"/issues/{number}"), json={"state": "closed"})
        return dict(resp.json())
