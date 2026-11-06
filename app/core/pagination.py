"""一覧APIで共通のページネーション処理（DRY）。

KEV/OSV/DEPSCAN の各一覧エンドポイントは、フィルタ適用済みの SQLAlchemy Query
から「件数カウント → offset 算出 → 並び替え・offset・limit を適用して取得」という
定型処理を共通で行っている。フィルタの構築自体（検索条件・絞り込み）はドメインごとに
大きく異なるため対象外とし、この定型部分のみを一元化する。
"""
from typing import Any, TypeVar

from sqlalchemy.orm import Query

T = TypeVar("T")

# 一覧APIのクエリパラメータの上限（各routerで同じ値を直書きしない）
DEFAULT_PER_PAGE = 50  # 1ページあたりの件数の既定値
MAX_PER_PAGE = 200  # 1ページあたりの件数の上限
MAX_PER_PAGE_LARGE = 500  # 件数が多い一覧（KEV）の上限
MAX_DAYS = 365  # 「直近N日」の上限


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
