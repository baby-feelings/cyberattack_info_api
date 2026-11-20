"""DEPSCAN 一覧 API の絞り込み条件（`ExceptableFindingFilter` のサブクラス）。"""
from typing import Any

from fastapi import Query
from sqlalchemy.orm import Query as SaQuery

from app.core.findings.operating_status import OperatingQuery
from app.depscan.models import DependencyFinding
from app.finding_exceptions.filters import ExceptableFindingFilter, include_excepted_query
from app.finding_exceptions.models import KIND_DEPENDENCY


class DepscanListFilter(ExceptableFindingFilter):
    """DEPSCAN 一覧のクエリパラメータ（リポジトリ・オーナー・エコシステム・重要度・解決状態）。"""

    model = DependencyFinding
    kind = KIND_DEPENDENCY

    def __init__(
        self,
        repo: str | None = Query(None, description="リポジトリ名絞り込み（例: owner/repo）"),
        owner: str | None = Query(
            None, description="リポジトリオーナー絞り込み（例: baby-feelings）"
        ),
        ecosystem: str | None = Query(None, description="エコシステム絞り込み（例: PyPI / npm）"),
        severity: str | None = Query(
            None, description="重要度絞り込み（CRITICAL / HIGH / MEDIUM / LOW）"
        ),
        resolved: bool | None = Query(None, description="解決状態で絞り込み（未指定なら全件）"),
        operating: OperatingQuery = "all",
        include_excepted: bool = include_excepted_query(),
    ) -> None:
        super().__init__(repo, owner, severity, resolved, operating, include_excepted)
        self.ecosystem = ecosystem

    def apply(self, query: SaQuery[Any]) -> SaQuery[Any]:
        query = super().apply(query)
        if self.ecosystem:
            query = query.filter(DependencyFinding.ecosystem == self.ecosystem)
        return query
