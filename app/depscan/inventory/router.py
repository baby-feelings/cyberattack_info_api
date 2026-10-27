"""使っている依存パッケージの閲覧・横断検索 API ルーター（DEPSCAN）。

GET /api/depscan/dependencies        – 依存パッケージの検索（どのリポジトリが、どの版か）
GET /api/depscan/dependencies/repos  – リポジトリごとの依存の数（閲覧画面の、リポジトリ一覧用）

DEPSCAN の他のエンドポイント（`app.depscan.router`）と同じ `/api/depscan` の下にあり、認証も
同じ（`X-API-KEY` または GitHub ログインのセッション。セッション認証時は本人所有のみに絞る）。
"""
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.auth.api_key import require_api_key_or_session
from app.core.database import get_db
from app.core.operating_status import OperatingQuery
from app.depscan.inventory.filters import DependencyFilter
from app.depscan.inventory.search import search_dependencies, summarize_repos
from app.depscan.sbom import build_purl
from app.depscan.schemas import (
    RepoDependencyListResponse,
    RepoDependencyOut,
    RepoDependencyRepoListResponse,
    RepoDependencyRepoStat,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/depscan", tags=["depscan"])


def dependency_filter(
    package: str | None = Query(None, description="パッケージ名（部分一致。例: undici）"),
    version: str | None = Query(None, description="バージョン（完全一致。例: 8.11.2）"),
    ecosystem: str | None = Query(None, description="エコシステム（例: PyPI / npm / Pub）"),
    repo: str | None = Query(None, description="リポジトリ（完全一致。例: owner/repo）"),
    vulnerable: bool = Query(False, description="true なら、未解決の検知がある依存のみ"),
    operating: OperatingQuery = "all",
) -> DependencyFilter:
    """クエリパラメータから、依存の絞り込み条件を作る。"""
    return DependencyFilter(
        package=package, version=version, ecosystem=ecosystem, repo=repo,
        vulnerable=vulnerable, operating=operating,
    )


def repo_list_filter(operating: OperatingQuery = "all") -> DependencyFilter:
    """リポジトリ一覧用の条件（運用状態だけで絞る）。"""
    return DependencyFilter(operating=operating)


@router.get(
    "/dependencies",
    response_model=RepoDependencyListResponse,
    summary="使っている依存パッケージの横断検索",
    description="どのリポジトリが、どのパッケージのどの版を使っているかを検索する"
    "（新しい脆弱性の影響範囲の確認用）。package は部分一致・大文字小文字を区別しない。"
    "各行の open_vulnerabilities は、その版に対する未解決の検知件数。"
    "依存の全量は DEPSCAN のスキャンごとに保存される。",
)
def search_repo_dependencies(
    db: Annotated[Session, Depends(get_db)],
    forced_owner: Annotated[str | None, Depends(require_api_key_or_session)],
    flt: Annotated[DependencyFilter, Depends(dependency_filter)],
    page: int = Query(1, ge=1, description="ページ番号（1始まり）"),
    per_page: int = Query(50, ge=1, le=200, description="1ページあたりの件数"),
) -> RepoDependencyListResponse:
    """依存パッケージを横断検索する。

    セッショントークン認証時は、ログイン中の GitHub ユーザー本人が所有するリポジトリのみに
    強制的に絞り込む（`GET /api/depscan` と同じ方針）。
    """
    flt = flt.for_owner(forced_owner)
    total, rows = search_dependencies(db, flt, page=page, per_page=per_page)
    logger.info("search_repo_dependencies: total=%d, page=%d, filter=%r", total, page, flt)
    data = [
        RepoDependencyOut.model_validate(dep).model_copy(update={
            "purl": build_purl(dep.ecosystem, dep.package_name, dep.version),
            "open_vulnerabilities": open_count,
        })
        for dep, open_count in rows
    ]
    return RepoDependencyListResponse(total=total, page=page, per_page=per_page, data=data)


@router.get(
    "/dependencies/repos",
    response_model=RepoDependencyRepoListResponse,
    summary="リポジトリごとの、使っている依存パッケージの数",
    description="リポジトリごとに、使っている依存の数と、うち未解決の検知がある依存の数を返す"
    "（対応が必要なリポジトリが先頭）。依存パッケージの閲覧画面の、リポジトリ一覧に使う。",
)
def list_dependency_repos(
    db: Annotated[Session, Depends(get_db)],
    forced_owner: Annotated[str | None, Depends(require_api_key_or_session)],
    flt: Annotated[DependencyFilter, Depends(repo_list_filter)],
) -> RepoDependencyRepoListResponse:
    """リポジトリ別の依存の数を返す。セッション認証時は本人所有のリポジトリのみ。"""
    rows = summarize_repos(db, flt.for_owner(forced_owner))
    return RepoDependencyRepoListResponse(repos=[
        RepoDependencyRepoStat(repo_full_name=repo, total=total, vulnerable=vulnerable)
        for repo, total, vulnerable in rows
    ])
