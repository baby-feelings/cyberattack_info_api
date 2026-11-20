"""例外（受容・影響なし・誤検知）の検知を含めるかを持つ、一覧の絞り込みの共通クラス。

DEPSCAN と CODESCAN の一覧は、どちらも `include_excepted` を受け取り、falseなら例外のある検知を
除く。この重複を、`RepoFindingFilter` の中間クラスにまとめる。`core/` は個別のドメインを知らない
ため、例外の知識（`not_excepted`）を持つこのクラスは、`finding_exceptions/` に置く。
"""
from typing import Any, ClassVar

from fastapi import Query
from sqlalchemy.orm import Query as SaQuery

from app.core.findings.list_filters import RepoFindingFilter
from app.core.findings.operating_status import OperatingStatus
from app.finding_exceptions.matching import not_excepted


def include_excepted_query() -> Any:
    """`include_excepted` クエリパラメータの定義（DEPSCAN / CODESCAN で同じ説明・既定値）。"""
    return Query(
        True,
        description="例外（受容・影響なし・誤検知）の検知を含める。falseなら対応が必要なもののみ",
    )


class ExceptableFindingFilter(RepoFindingFilter):
    """例外の検知を含めるかを持つ絞り込み（サブクラスが、例外の種別 `kind` を宣言する）。"""

    # 例外の種別（`KIND_DEPENDENCY` / `KIND_CODE`）
    kind: ClassVar[str]

    def __init__(
        self,
        repo: str | None,
        owner: str | None,
        severity: str | None,
        resolved: bool | None,
        operating: OperatingStatus,
        include_excepted: bool,
    ) -> None:
        super().__init__(repo, owner, severity, resolved, operating)
        self.include_excepted = include_excepted

    def apply(self, query: SaQuery[Any]) -> SaQuery[Any]:
        query = super().apply(query)
        # 例外にした検知を除く（ダッシュボードの初期表示。件数の集計と同じ基準にそろえる）
        if not self.include_excepted:
            query = not_excepted(query, self.kind)
        return query
