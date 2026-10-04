"""CODESCAN 一覧 API の絞り込み条件（`RepoFindingFilter` のサブクラス）。"""
from typing import Any

from fastapi import Query
from sqlalchemy.orm import Query as SaQuery

from app.codescan.models import CodeFinding
from app.core.list_filters import RepoFindingFilter


class CodescanListFilter(RepoFindingFilter):
    """CODESCAN 一覧のクエリパラメータ（リポジトリ・オーナー・重要度・解決状態・CVSS 下限）。"""

    model = CodeFinding

    def __init__(
        self,
        repo: str | None = Query(None, description="リポジトリ名絞り込み（例: owner/repo）"),
        owner: str | None = Query(
            None, description="リポジトリオーナー絞り込み（例: baby-feelings）"
        ),
        severity: str | None = Query(None, description="重要度絞り込み（ERROR/WARNING/INFO）"),
        resolved: bool | None = Query(None, description="解決状態で絞り込み（未指定なら全件）"),
        min_cvss: float | None = Query(
            None, ge=0, le=10, description="CVSS基本値の下限値で絞り込み"
        ),
    ) -> None:
        super().__init__(repo, owner, severity, resolved)
        self.min_cvss = min_cvss

    def apply(self, query: SaQuery[Any]) -> SaQuery[Any]:
        query = super().apply(query)
        if self.min_cvss is not None:
            query = query.filter(CodeFinding.cvss_score >= self.min_cvss)
        return query
