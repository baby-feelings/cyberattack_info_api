"""リポジトリの所有者（オーナー）による絞り込み・所有の判定。

セッション認証（GitHub ログイン）のときは、ログイン中のユーザー本人が所有するリポジトリ
（`owner/name` の `owner` が一致するもの）だけを返す。この判定が、DEPSCAN の依存の検索・
言語バージョンの閲覧・一覧の絞り込み・SBOM のエクスポートに重複していたため、ここに集約する
（他のユーザーのリポジトリを見せない、という重要な制限が、場所ごとにずれないようにするため）。

前方一致で判定する。`LIKE 'owner/%'` では、オーナー名に含まれる `_` がワイルドカードとして
働き、別のオーナー（`a_b` に対する `aXb`）に一致してしまうため。
"""
from typing import Any

from sqlalchemy.orm import Query


def owner_prefix(owner: str) -> str:
    """リポジトリの完全名（`owner/name`）の、そのオーナーの接頭辞。"""
    return f"{owner}/"


def is_owned_by(repo_full_name: str, owner: str) -> bool:
    """リポジトリ（`owner/name`）が、そのオーナーのものか。"""
    return repo_full_name.startswith(owner_prefix(owner))


def restrict_to_owner(query: Query[Any], column: Any, owner: str | None) -> Query[Any]:
    """クエリを、そのオーナーのリポジトリのみに絞る。`owner` が None（API キー認証）なら絞らない。

    Args:
        column: リポジトリの完全名（`owner/name`）の列
    """
    if owner is None:
        return query
    return query.filter(column.startswith(owner_prefix(owner), autoescape=True))
