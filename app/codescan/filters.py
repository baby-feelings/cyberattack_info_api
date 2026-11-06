"""CODESCAN 一覧 API の絞り込み条件（`RepoFindingFilter` のサブクラス）。"""
from typing import Any

from fastapi import Query
from sqlalchemy.orm import Query as SaQuery

from app.codescan.models import CodeFinding
from app.core.findings.list_filters import RepoFindingFilter
from app.core.findings.operating_status import OperatingQuery
from app.finding_exceptions.matching import not_excepted
from app.finding_exceptions.models import KIND_CODE


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
        operating: OperatingQuery = "all",
        include_excepted: bool = Query(
            True,
            description="例外（受容・影響なし・誤検知）の検知を含める。falseなら対応が必要なもののみ",
        ),
    ) -> None:
        super().__init__(repo, owner, severity, resolved, operating)
        self.include_excepted = include_excepted
        self.min_cvss = min_cvss

    def apply(self, query: SaQuery[Any]) -> SaQuery[Any]:
        query = super().apply(query)
        # 例外にした検知を除く（ダッシュボードの初期表示。件数の集計と同じ基準にそろえる）
        if not self.include_excepted:
            query = not_excepted(query, KIND_CODE)
        if self.min_cvss is not None:
            query = query.filter(CodeFinding.cvss_score >= self.min_cvss)
        return query
