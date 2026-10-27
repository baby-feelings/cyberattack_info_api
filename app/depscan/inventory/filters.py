"""依存パッケージの絞り込み条件（検索条件の値オブジェクト）。

検索・集計の関数に、条件ごとの引数（10個）を並べて渡していたものを、1つのオブジェクトに
まとめる。ルーターは、クエリパラメータからこのオブジェクトを作り（`router.py`）、検索・集計は、
オブジェクト自身に `apply` させる（Tell, Don't Ask）。DB にもリクエストにも依存しない値のため、
テストでは、そのまま作って渡せる。
"""
from dataclasses import dataclass, replace
from typing import Any

from sqlalchemy import exists
from sqlalchemy.orm import Query

from app.core.operating_status import OperatingStatus, apply_operating_status
from app.core.owner_scope import restrict_to_owner
from app.depscan.models import DependencyFinding, RepoDependency


def has_open_finding() -> Any:
    """その依存（リポジトリ・エコシステム・パッケージ・版が一致）に、未解決の検知がある、という条件。"""
    return exists().where(
        DependencyFinding.resolved_at.is_(None),
        DependencyFinding.repo_full_name == RepoDependency.repo_full_name,
        DependencyFinding.ecosystem == RepoDependency.ecosystem,
        DependencyFinding.package_name == RepoDependency.package_name,
        DependencyFinding.installed_version == RepoDependency.version,
    )


@dataclass(frozen=True)
class DependencyFilter:
    """依存パッケージの絞り込み条件。未指定（None・False・all）の条件は、絞り込まない。

    Attributes:
        package: パッケージ名（部分一致・大文字小文字を区別しない）
        version: バージョン（完全一致）
        ecosystem: エコシステム（完全一致。例: PyPI / npm / Pub）
        repo: リポジトリ（完全一致。例: owner/repo）
        vulnerable: True なら、未解決の検知がある依存だけ
        operating: 運用状態（運用中／運用停止中／すべて）
        owner: 指定した場合、そのオーナーのリポジトリのみに強制的に絞る
            （セッション認証時に、本人所有のリポジトリ以外を返さないため）
    """

    package: str | None = None
    version: str | None = None
    ecosystem: str | None = None
    repo: str | None = None
    vulnerable: bool = False
    operating: OperatingStatus = "all"
    owner: str | None = None

    def for_owner(self, owner: str | None) -> "DependencyFilter":
        """所有者の制限を加えた、新しい条件を返す（セッション認証は本人のみ、API キーは None）。"""
        return replace(self, owner=owner)

    def apply(self, query: Query[Any]) -> Query[Any]:
        """`RepoDependency` のクエリに、全ての条件を適用する。"""
        query = apply_operating_status(
            restrict_to_owner(query, RepoDependency.repo_full_name, self.owner),
            RepoDependency.repo_full_name, self.operating,
        )
        if self.package:
            query = query.filter(
                RepoDependency.package_name.icontains(self.package, autoescape=True),
            )
        if self.version:
            query = query.filter(RepoDependency.version == self.version)
        if self.ecosystem:
            query = query.filter(RepoDependency.ecosystem == self.ecosystem)
        if self.repo:
            query = query.filter(RepoDependency.repo_full_name == self.repo)
        if self.vulnerable:
            query = query.filter(has_open_finding())
        return query
