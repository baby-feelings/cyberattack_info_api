"""言語・実行環境のバージョン監視（RUNTIME）API ルーター。

GET /api/runtimes           – 使っている言語・実行環境の一覧（状態つき。各種の絞り込み）
GET /api/runtimes/repos     – リポジトリごとの件数（閲覧画面の、左のリポジトリ一覧用）
GET /api/runtimes/releases  – 最新版とサポート期限の一覧

DEPSCAN と同じく、`X-API-KEY` または GitHub ログインのセッションを要求し、セッション認証時は
本人所有のリポジトリのみに強制的に絞り込む（他のユーザーのリポジトリ名・使っている版を
見せないため）。
"""
import logging
from datetime import UTC, date, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Security
from sqlalchemy.orm import Session

from app.auth.api_key import require_api_key, require_api_key_or_session
from app.core.background import run_in_background
from app.core.database import get_db
from app.core.operating_status import OperatingQuery
from app.runtimes.browse import list_runtimes, summarize_repos
from app.runtimes.crawler import fetch_and_scan_runtimes
from app.runtimes.detector import RUNTIME_LABELS, RUNTIMES
from app.runtimes.models import RuntimeRelease
from app.runtimes.schemas import (
    RepoRuntimeListResponse,
    RepoRuntimeOut,
    RepoRuntimeRepoListResponse,
    RepoRuntimeRepoStat,
    RuntimeCrawlResponse,
    RuntimeReleaseListResponse,
    RuntimeReleaseOut,
)
from app.runtimes.status import cycle_key, recommended_release

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/runtimes", tags=["runtimes"])

# 管理者用エンドポイント（/admin/runtime-crawl）。prefix なし・require_api_key で保護する。
admin_router = APIRouter(tags=["admin"])


def _today() -> date:
    """判定の基準にする今日（UTC）。"""
    return datetime.now(UTC).date()


def _iso(value: date | None) -> str | None:
    return value.isoformat() if value else None


@admin_router.post(
    "/admin/runtime-crawl",
    dependencies=[Security(require_api_key)],
    summary="言語・実行環境のバージョン監視の手動実行（バックグラウンド）",
    description="最新版・サポート期限の更新と、各リポジトリが使っている版の検出を"
    "バックグラウンドで開始する（X-API-KEY 必須）。結果は /api/crawler-logs で確認。",
    status_code=202,
)
def trigger_runtime_crawl(
    force: bool = Query(False, description="今日すでに成功実行済みでも強制的に再実行する"),
) -> RuntimeCrawlResponse:
    """言語・実行環境のバージョン監視をバックグラウンドで実行する。"""
    logger.info("Manual RUNTIME triggered via /admin/runtime-crawl (force=%s)", force)
    run_in_background("RUNTIME", lambda: fetch_and_scan_runtimes(force=force))
    return RuntimeCrawlResponse(message="Runtime version scan started in background")


@router.get(
    "",
    response_model=RepoRuntimeListResponse,
    summary="使っている言語・実行環境の一覧",
    description="リポジトリごとに、使っている Python・Node.js・Flutter・Dart の版と、"
    "最新版・サポート期限から判定した状態を返す（対応が急ぐものが先頭）。"
    "needs_action=true で、期限切れ・期限間近・更新ありのものだけに絞る。",
)
def list_repo_runtimes(
    db: Annotated[Session, Depends(get_db)],
    forced_owner: Annotated[str | None, Depends(require_api_key_or_session)],
    repo: str | None = Query(None, description="リポジトリ（完全一致。例: owner/repo）"),
    runtime: str | None = Query(None, description="python / nodejs / flutter / dart"),
    needs_action: bool = Query(False, description="true なら、対応が必要なもののみ"),
    operating: OperatingQuery = "all",
) -> RepoRuntimeListResponse:
    """使っている言語・実行環境を、状態つきで返す。セッション認証時は本人所有のみ。"""
    rows = list_runtimes(
        db, today=_today(), forced_owner=forced_owner, repo=repo,
        runtime=runtime if runtime in RUNTIMES else None,
        needs_action=needs_action, operating=operating,
    )
    data = [
        RepoRuntimeOut(
            repo_full_name=row.repo_full_name,
            runtime=row.runtime,
            runtime_label=RUNTIME_LABELS.get(row.runtime, row.runtime),
            cycle=row.cycle,
            source_path=row.source_path,
            pinned=row.pinned,
            state=st.state,
            latest_version=st.latest_version,
            recommended_cycle=st.recommended_cycle,
            recommended_version=st.recommended_version,
            eol_date=_iso(st.eol_date),
            days_to_eol=st.days_to_eol,
        )
        for row, st in rows
    ]
    logger.info(
        "list_repo_runtimes: total=%d, repo=%r, runtime=%r, needs_action=%r, operating=%r",
        len(data), repo, runtime, needs_action, operating,
    )
    return RepoRuntimeListResponse(total=len(data), data=data)


@router.get(
    "/repos",
    response_model=RepoRuntimeRepoListResponse,
    summary="リポジトリごとの、使っている言語・実行環境の数",
    description="リポジトリごとに、検出した言語・実行環境の数と、うち対応が必要な数を返す"
    "（対応が必要なリポジトリが先頭）。閲覧画面の、リポジトリ一覧に使う。",
)
def list_runtime_repos(
    db: Annotated[Session, Depends(get_db)],
    forced_owner: Annotated[str | None, Depends(require_api_key_or_session)],
    operating: OperatingQuery = "all",
) -> RepoRuntimeRepoListResponse:
    """リポジトリ別の件数を返す。セッション認証時は本人所有のリポジトリのみ。"""
    rows = summarize_repos(db, today=_today(), forced_owner=forced_owner, operating=operating)
    return RepoRuntimeRepoListResponse(repos=[
        RepoRuntimeRepoStat(repo_full_name=repo, total=total, needs_action=needs)
        for repo, total, needs in rows
    ])


@router.get(
    "/releases",
    response_model=RuntimeReleaseListResponse,
    summary="言語・実行環境の最新版とサポート期限",
    description="Python・Node.js・Flutter・Dart の、バージョン系列ごとの最新版とサポート期限"
    "（言語ごとに新しい系列が先頭）。recommended が、推奨の系列。",
)
def list_runtime_releases(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[str | None, Depends(require_api_key_or_session)],
) -> RuntimeReleaseListResponse:
    """最新版・サポート期限の一覧を返す（リポジトリの情報を含まないため、本人所有の絞り込みは不要）。"""
    releases = db.query(RuntimeRelease).all()
    data: list[RuntimeReleaseOut] = []
    for runtime in RUNTIMES:
        own = sorted(
            (r for r in releases if r.runtime == runtime),
            key=lambda r: cycle_key(r.cycle), reverse=True,
        )
        recommended = recommended_release(runtime, own, _today())
        data.extend(
            RuntimeReleaseOut(
                runtime=r.runtime,
                runtime_label=RUNTIME_LABELS.get(r.runtime, r.runtime),
                cycle=r.cycle,
                latest_version=r.latest_version,
                release_date=_iso(r.release_date),
                eol_date=_iso(r.eol_date),
                is_eol=r.is_eol,
                is_lts=r.is_lts,
                recommended=recommended is not None and recommended.cycle == r.cycle,
            )
            for r in own
        )
    return RuntimeReleaseListResponse(data=data)
