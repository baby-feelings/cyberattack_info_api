"""OSV 一覧 API の絞り込み条件（`FeedListFilter` のサブクラス）。"""
from datetime import datetime
from typing import Any, Literal

from fastapi import Query
from sqlalchemy.orm import Query as SaQuery

from app.core.list_filters import FeedListFilter
from app.osv.models import OsvVulnerability


class OsvListFilter(FeedListFilter):
    """OSV 一覧のクエリパラメータ（直近日数・エコシステム・重要度・検索・ソート・差分取得）。"""

    model = OsvVulnerability
    date_column = "modified"
    search_columns = ("osv_id", "package_name", "summary")
    # 重要度は大文字統一（high → HIGH）
    normalize_severity = str.upper

    def __init__(
        self,
        days: int = Query(30, ge=1, le=365, description="直近何日分を取得するか"),
        ecosystem: str | None = Query(None, description="エコシステム絞り込み（例: PyPI / npm）"),
        severity: str | None = Query(
            None, description="重要度絞り込み（CRITICAL / HIGH / MEDIUM / LOW）"
        ),
        search: str | None = Query(
            None, description="OSV ID・パッケージ名・概要のキーワード検索"
        ),
        sort_by: Literal["modified", "cvss"] = Query(
            "modified",
            description="ソートキー（modified: 更新日時降順 / cvss: CVSSスコア降順）",
        ),
        updated_since: datetime | None = Query(
            None,
            description="この日時以降に内容が更新されたレコードのみ返す（差分取得用、ISO 8601）",
        ),
    ) -> None:
        super().__init__(days, severity, search, sort_by, updated_since)
        self.ecosystem = ecosystem

    def apply(self, query: SaQuery[Any]) -> SaQuery[Any]:
        query = super().apply(query)
        # エコシステムフィルタ（完全一致）
        if self.ecosystem:
            query = query.filter(OsvVulnerability.ecosystem == self.ecosystem)
        return query
