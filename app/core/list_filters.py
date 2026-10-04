"""一覧 API の絞り込み条件（クエリパラメータ）を表す共通クラス。

各ドメインの `router.py` が、8〜9 個のクエリパラメータの受け取りと、似通ったフィルター処理を
個別に繰り返していた。クエリパラメータの定義と `Query` への適用を「検索条件オブジェクト」に
まとめ、ルーターは `Depends()` で受け取って `apply` を呼ぶだけにする（関心の分離）。

FastAPI は `Depends()` に渡したクラスの `__init__` 引数をクエリパラメータとして展開する。
そのため OpenAPI 上のパラメータ名・制約・説明は、従来のエンドポイント引数と変わらない
（サブクラスは自身の `__init__` で `Query(...)` を宣言する）。

- `FeedListFilter`: OSV / JVN 共通（直近 N 日・重要度・キーワード・ソート・差分取得）
- `RepoFindingFilter`: DEPSCAN / CODESCAN 共通（リポジトリ・オーナー・重要度・解決状態）
"""
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar, Literal

from fastapi import HTTPException, status
from sqlalchemy import or_
from sqlalchemy.orm import Query as SaQuery


class FeedListFilter:
    """OSV / JVN の一覧絞り込み（サブクラスが対象モデルと列を宣言する）。"""

    # サブクラスで宣言する: 対象モデル・「直近 N 日」の基準列名・キーワード検索対象の列名・
    # CVSS 以外のデフォルトソート列名・重要度の正規化方法
    model: ClassVar[Any]
    date_column: ClassVar[str]
    search_columns: ClassVar[tuple[str, ...]]
    normalize_severity: ClassVar[Callable[[str], str]]

    def __init__(
        self,
        days: int,
        severity: str | None,
        search: str | None,
        sort_by: Literal["modified", "cvss"],
        updated_since: datetime | None,
    ) -> None:
        self.days = days
        self.severity = severity
        self.search = search
        self.sort_by = sort_by
        self.updated_since = updated_since

    def base_query(self, db: Any) -> SaQuery[Any]:
        """直近 `days` 日以内に更新されたレコードに絞った出発点のクエリ。"""
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.days)
        return db.query(self.model).filter(getattr(self.model, self.date_column) >= cutoff)

    def apply(self, query: SaQuery[Any]) -> SaQuery[Any]:
        """差分取得・重要度・キーワードの各条件を適用する。"""
        model = self.model
        # 差分取得（増分同期）: 新規追加または内容変更があったレコードのみに絞り込む
        if self.updated_since is not None:
            query = query.filter(model.updated_at >= self.updated_since)
        if self.severity:
            query = query.filter(model.severity == type(self).normalize_severity(self.severity))
        if self.search:
            keyword = f"%{self.search}%"
            query = query.filter(
                or_(*(getattr(model, col).ilike(keyword) for col in self.search_columns)),
            )
        return query

    def order(self) -> Any:
        """ソート順。cvss 指定時は CVSS スコア降順（NULL は末尾）、それ以外は更新日時降順。"""
        if self.sort_by == "cvss":
            return self.model.cvss_score.desc().nulls_last()
        return getattr(self.model, self.date_column).desc()


class RepoFindingFilter:
    """DEPSCAN / CODESCAN の検知結果の絞り込み（リポジトリ・オーナー・重要度・解決状態）。

    サブクラスが対象モデル（`repo_full_name` / `severity` / `resolved_at` 列を持つこと）を宣言する。
    """

    model: ClassVar[Any]

    def __init__(
        self,
        repo: str | None,
        owner: str | None,
        severity: str | None,
        resolved: bool | None,
    ) -> None:
        self.repo = repo
        self.owner = owner
        self.severity = severity
        self.resolved = resolved

    def restrict_to_owner(self, forced_owner: str | None) -> None:
        """セッション認証時、ログイン中ユーザー本人が所有するリポジトリのみに強制的に絞り込む。

        `repo` は owner とは独立した完全一致フィルタのため、他人のリポジトリを直接指定して
        owner 制限を迂回できないようガードする（403）。API キー認証時（None）は何もしない。
        """
        if forced_owner is None:
            return
        self.owner = forced_owner
        if self.repo is not None and not self.repo.startswith(f"{forced_owner}/"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only query repositories you own.",
            )

    def apply(self, query: SaQuery[Any]) -> SaQuery[Any]:
        """共通の各条件（リポジトリ・オーナー・重要度・解決状態）を適用する。"""
        model = self.model
        if self.repo:
            query = query.filter(model.repo_full_name == self.repo)
        if self.owner:
            query = query.filter(model.repo_full_name.like(f"{self.owner}/%"))
        if self.severity:
            query = query.filter(model.severity == self.severity.upper())
        if self.resolved is not None:
            if self.resolved:
                query = query.filter(model.resolved_at.is_not(None))
            else:
                query = query.filter(model.resolved_at.is_(None))
        return query
