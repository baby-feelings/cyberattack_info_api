"""リポジトリの運用状態（運用中／運用停止中）による絞り込み。

アプリの運用を止めたリポジトリ（`INACTIVE_REPOS` に列挙）の脆弱性を、運用中のものと分けて
見られるように、DEPSCAN・CODESCAN・DEPSOPS の一覧・統計 API が共通で使う。

- 運用状態は検知結果には保存せず、**取得のたびに設定と照合して判定する**。運用を再開するときは
  `INACTIVE_REPOS` から外して再起動するだけで、過去の検知も含めてすぐに入れ替わる
  （データの移行は不要）
- 一覧に載っていないリポジトリは「運用中」として扱う
- スキャン自体は止めない（止めるのは `SCAN_EXCLUDE_REPOS`）
"""
from typing import Annotated, Any, Literal

from fastapi import Query
from sqlalchemy import func
from sqlalchemy.orm import Query as SaQuery

from app.core.config import settings

# active=運用中のみ / inactive=運用停止中のみ / all=すべて
OperatingStatus = Literal["active", "inactive", "all"]

# 一覧・統計 API のクエリパラメータ（`operating=active|inactive|all`。
# 未指定は all で、従来どおり全件）
OperatingQuery = Annotated[
    OperatingStatus,
    Query(description="運用状態で絞り込み（active=運用中 / inactive=運用停止中 / all=すべて）"),
]


def inactive_repo_names() -> set[str]:
    """`INACTIVE_REPOS`（カンマ区切りの `owner/name`）を、小文字の集合にして返す。"""
    return {e.strip().lower() for e in settings.INACTIVE_REPOS.split(",") if e.strip()}


def is_inactive_repo(full_name: str) -> bool:
    """運用停止中に指定されたリポジトリか（大文字小文字は区別しない）。"""
    return full_name.lower() in inactive_repo_names()


def apply_operating_status(
    query: SaQuery[Any], repo_column: Any, operating: OperatingStatus,
) -> SaQuery[Any]:
    """`repo_column`（`repo_full_name` 列）を、運用状態で絞り込む。`all` ならそのまま返す。"""
    if operating == "all":
        return query
    inactive = inactive_repo_names()
    in_inactive = func.lower(repo_column).in_(inactive)
    return query.filter(in_inactive if operating == "inactive" else ~in_inactive)
