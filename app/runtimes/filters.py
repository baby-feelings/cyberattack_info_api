"""使っている言語・実行環境の絞り込み条件（検索条件の値オブジェクト）。

閲覧・集計の関数に、条件ごとの引数を並べて渡していたものを、1つのオブジェクトにまとめる
（依存パッケージの `app.depscan.inventory.filters` と同じ作り）。DB にもリクエストにも
依存しない値のため、テストでは、そのまま作って渡せる。
"""
from dataclasses import dataclass, replace
from typing import Any

from sqlalchemy.orm import Query

from app.core.operating_status import OperatingStatus, apply_operating_status
from app.core.owner_scope import restrict_to_owner
from app.runtimes.models import RepoRuntime


@dataclass(frozen=True)
class RuntimeFilter:
    """言語・実行環境の絞り込み条件。未指定（None・False・all）の条件は、絞り込まない。

    Attributes:
        repo: リポジトリ（完全一致。例: owner/repo）
        runtime: 言語・実行環境（python / nodejs / flutter / dart）
        needs_action: True なら、対応が必要な状態（期限切れ・期限間近・更新あり）のみ。
            状態は、使っている版とリリース情報から求めるため、DB の絞り込み（`apply`）では扱わない
        operating: 運用状態（運用中／運用停止中／すべて）
        owner: 指定した場合、そのオーナーのリポジトリのみに強制的に絞る
            （セッション認証時に、本人所有のリポジトリ以外を返さないため）
    """

    repo: str | None = None
    runtime: str | None = None
    needs_action: bool = False
    operating: OperatingStatus = "all"
    owner: str | None = None

    def for_owner(self, owner: str | None) -> "RuntimeFilter":
        """所有者の制限を加えた、新しい条件を返す（セッション認証は本人のみ、API キーは None）。"""
        return replace(self, owner=owner)

    def apply(self, query: Query[Any]) -> Query[Any]:
        """`RepoRuntime` のクエリに、DB で絞れる条件（所有者・リポジトリ・言語・運用状態）を適用"""
        query = restrict_to_owner(query, RepoRuntime.repo_full_name, self.owner)
        if self.repo:
            query = query.filter(RepoRuntime.repo_full_name == self.repo)
        if self.runtime:
            query = query.filter(RepoRuntime.runtime == self.runtime)
        return apply_operating_status(query, RepoRuntime.repo_full_name, self.operating)
