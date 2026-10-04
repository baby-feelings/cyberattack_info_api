"""KEV 一覧 API の絞り込み条件。"""
from datetime import datetime
from typing import Any

from fastapi import Query
from sqlalchemy import or_
from sqlalchemy.orm import Query as SaQuery

from app.kev.models import Vulnerability


class KevListFilter:
    """KEV 一覧のクエリパラメータ（キーワード・ベンダー・製品・EPSS 下限・差分取得）。"""

    def __init__(
        self,
        search: str | None = Query(None, description="ベンダー名・製品名の部分一致検索"),
        vendor: str | None = Query(None, description="ベンダー名での絞り込み（完全一致）"),
        product: str | None = Query(None, description="製品名での絞り込み（部分一致）"),
        min_epss: float | None = Query(
            None, ge=0.0, le=1.0,
            description="EPSS スコアの下限（0.0〜1.0）。指定値以上のもののみ返す",
        ),
        updated_since: datetime | None = Query(
            None,
            description="この日時以降に内容が更新されたレコードのみ返す（差分取得用、ISO 8601）",
        ),
    ) -> None:
        self.search = search
        self.vendor = vendor
        self.product = product
        self.min_epss = min_epss
        self.updated_since = updated_since

    def apply(self, query: SaQuery[Any]) -> SaQuery[Any]:
        # キーワード検索: ベンダー名 OR 製品名の部分一致
        if self.search:
            keyword = f"%{self.search}%"
            query = query.filter(
                or_(
                    Vulnerability.vendor_project.ilike(keyword),
                    Vulnerability.product.ilike(keyword),
                )
            )
        # ベンダー名の完全一致フィルタ
        if self.vendor:
            query = query.filter(Vulnerability.vendor_project == self.vendor)
        # 製品名の部分一致フィルタ
        if self.product:
            query = query.filter(Vulnerability.product.ilike(f"%{self.product}%"))
        # EPSS スコアの下限フィルタ
        if self.min_epss is not None:
            query = query.filter(Vulnerability.epss_score >= self.min_epss)
        # 差分取得（増分同期）: 新規追加または内容変更があったレコードのみに絞り込む
        if self.updated_since is not None:
            query = query.filter(Vulnerability.updated_at >= self.updated_since)
        return query
