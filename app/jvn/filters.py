"""JVN 一覧 API の絞り込み条件（`FeedListFilter` のサブクラス）。"""
from datetime import datetime
from typing import Literal

from fastapi import Query

from app.core.list_filters import FeedListFilter
from app.jvn.models import JvnVulnerability


class JvnListFilter(FeedListFilter):
    """JVN 一覧のクエリパラメータ（直近日数・重要度・キーワード・ソート・差分取得）。"""

    model = JvnVulnerability
    date_column = "date_last_modified"
    search_columns = ("jvndb_id", "title", "overview")
    # 重要度は先頭大文字統一（high → High）
    normalize_severity = str.capitalize

    def __init__(
        self,
        days: int = Query(30, ge=1, le=365, description="直近何日分を取得するか"),
        severity: str | None = Query(
            None, description="重要度絞り込み（High / Medium / Low）"
        ),
        search: str | None = Query(
            None, description="JVNDB ID・タイトル・概要のキーワード検索"
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
