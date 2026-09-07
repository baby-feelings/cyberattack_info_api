"""一覧APIで共通のページネーション処理（DRY）。

KEV/OSV/JVN/DEPSCAN の各一覧エンドポイントは、フィルタ適用済みの SQLAlchemy Query
から「件数カウント → offset 算出 → 並び替え・offset・limit を適用して取得」という
定型処理を共通で行っている。フィルタの構築自体（検索条件・絞り込み）はドメインごとに
大きく異なるため対象外とし、この定型部分のみを一元化する。
"""
from typing import Any, TypeVar

from sqlalchemy.orm import Query

T = TypeVar("T")


def paginate(query: "Query[T]", page: int, per_page: int, order_by: Any) -> tuple[int, list[T]]:
    """クエリに件数カウント・並び替え・ページネーションを適用する。

    Args:
        query: フィルタ適用済みの SQLAlchemy Query
        page: ページ番号（1始まり）
        per_page: 1ページあたりの件数
        order_by: order_by() に渡すカラム/式（例: Model.field.desc()）

    Returns:
        (総件数, そのページのレコードリスト) のタプル
    """
    total = query.count()
    offset = (page - 1) * per_page
    items = query.order_by(order_by).offset(offset).limit(per_page).all()
    return total, items
