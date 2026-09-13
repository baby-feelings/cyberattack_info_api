"""依存ライブラリ脆弱性スキャン（DEPSCAN）API ルーター。

GET /api/depscan        – 検知結果一覧（リポジトリ・エコシステム・重要度・解決状態でフィルタ）
GET /api/depscan/stats  – リポジトリ別・重要度別の統計情報（未解決分のみ集計）

認証は `X-API-KEY`（フルアクセス）または `Authorization: Bearer <セッショントークン>`
（GitHub ログイン経由。本人所有リポジトリのみに強制的に絞り込む）のいずれかを受け付ける。
"""
import hmac
import json
import logging
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response, Security, status
from fastapi.security import APIKeyHeader
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.auth.session import decode_session_token
from app.core.auth import require_api_key, require_public_api_key
from app.core.background import run_in_background
from app.core.config import settings
from app.core.database import get_db
from app.core.pagination import paginate
from app.core.schemas import SeverityStat
from app.depscan.crawler import fetch_and_scan_dependencies
from app.depscan.models import DependencyFinding, RepoAssetContext
from app.depscan.sbom import build_cyclonedx_sbom, build_purl, build_spdx_sbom
from app.depscan.schemas import (
    DependencyFindingListResponse,
    DependencyFindingOut,
    DependencyFindingStatsResponse,
    RepoAssetContextIn,
    RepoAssetContextListResponse,
    RepoAssetContextOut,
    RepoStat,
)
from app.kev.models import Vulnerability

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/depscan", tags=["depscan"])

# EPSSスコアがこの値以上なら"epss_high"理由を付与する（Issue #135）。
# FIRSTのEPSS運用ガイドでは明確な閾値は定義されていないが、0.5は一般的に
# 「悪用確率が偶然を上回る」目安として引用される値
_EPSS_HIGH_THRESHOLD = 0.5

# 管理者用エンドポイント（/admin/depscan-crawl）。prefix なし・require_api_key で保護する。
admin_router = APIRouter(tags=["admin"])


@admin_router.post(
    "/admin/depscan-crawl",
    dependencies=[Security(require_api_key)],
    summary="依存ライブラリ脆弱性スキャン手動実行（バックグラウンド）",
    description="GitHub 上の対象リポジトリのロックファイルを OSV API と照合する処理を"
    "バックグラウンドで開始する（X-API-KEY 必須）。結果は /api/crawler-logs で確認。",
    status_code=202,
)
def trigger_depscan_crawl() -> dict:
    """依存ライブラリ脆弱性スキャナーをバックグラウンドで実行する。"""
    logger.info("Manual DEPSCAN triggered via /admin/depscan-crawl")
    run_in_background("DEPSCAN", fetch_and_scan_dependencies)
    return {"message": "Dependency vulnerability scan started in background"}

_api_key_header = APIKeyHeader(name="X-API-KEY", auto_error=False)
_bearer_header = APIKeyHeader(name="Authorization", auto_error=False)


def _resolve_access(
    api_key: str | None = Depends(_api_key_header),
    authorization: str | None = Depends(_bearer_header),
) -> str | None:
    """`X-API-KEY` または `Authorization: Bearer <session token>` を検証する。

    Returns:
        セッショントークン認証の場合はログイン中の GitHub ユーザー名
        （呼び出し側でこの値に強制的に絞り込む）。API キー認証の場合は
        None（絞り込みなし＝フルアクセス。Claude Code 等の既存クライアント向け）。
    """
    if api_key and hmac.compare_digest(api_key, settings.API_KEY):
        return None
    if authorization and authorization.lower().startswith("bearer "):
        username = decode_session_token(authorization[len("bearer "):].strip())
        if username is not None:
            return username
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid or missing credentials. Provide X-API-KEY or "
        "Authorization: Bearer <session token>.",
    )


@router.get(
    "",
    response_model=DependencyFindingListResponse,
    summary="依存ライブラリ脆弱性の検知結果一覧取得",
    description="リポジトリ・エコシステム・重要度・解決状態でフィルタリング可能。",
)
def list_depscan(
    db: Annotated[Session, Depends(get_db)],
    forced_owner: Annotated[str | None, Depends(_resolve_access)],
    page: int = Query(1, ge=1, description="ページ番号（1始まり）"),
    per_page: int = Query(50, ge=1, le=200, description="1ページあたりの件数"),
    repo: str | None = Query(None, description="リポジトリ名絞り込み（例: owner/repo）"),
    owner: str | None = Query(None, description="リポジトリオーナー絞り込み（例: baby-feelings）"),
    ecosystem: str | None = Query(None, description="エコシステム絞り込み（例: PyPI / npm）"),
    severity: str | None = Query(
        None, description="重要度絞り込み（CRITICAL / HIGH / MEDIUM / LOW）"
    ),
    resolved: bool | None = Query(None, description="解決状態で絞り込み（未指定なら全件）"),
) -> DependencyFindingListResponse:
    """依存ライブラリ脆弱性の検知結果を取得する。

    セッショントークン認証時は `owner` クエリパラメータの指定に関わらず、
    ログイン中の GitHub ユーザー本人が所有するリポジトリのみに強制的に絞り込む。
    """
    if forced_owner is not None:
        owner = forced_owner
        # `repo` は owner とは独立した完全一致フィルタのため、セッション認証時に
        # 他人のリポジトリを直接指定して owner 制限を迂回できないようガードする
        if repo is not None and not repo.startswith(f"{forced_owner}/"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You can only query repositories you own.",
            )

    query = db.query(DependencyFinding)

    if repo:
        query = query.filter(DependencyFinding.repo_full_name == repo)
    if owner:
        query = query.filter(DependencyFinding.repo_full_name.like(f"{owner}/%"))
    if ecosystem:
        query = query.filter(DependencyFinding.ecosystem == ecosystem)
    if severity:
        query = query.filter(DependencyFinding.severity == severity.upper())
    if resolved is not None:
        if resolved:
            query = query.filter(DependencyFinding.resolved_at.is_not(None))
        else:
            query = query.filter(DependencyFinding.resolved_at.is_(None))

    total, items = paginate(query, page, per_page, DependencyFinding.detected_at.desc())

    logger.info(
        "list_depscan: total=%d, page=%d, repo=%r, owner=%r, ecosystem=%r, "
        "severity=%r, resolved=%r",
        total, page, repo, owner, ecosystem, severity, resolved,
    )

    asset_context_map = _fetch_asset_context_map(
        db, {item.repo_full_name for item in items},
    )
    kev_map = _fetch_kev_map(db, items)

    data = []
    for item in items:
        asset_context = asset_context_map.get(item.repo_full_name)
        data.append(DependencyFindingOut.model_validate(item).model_copy(update={
            "asset_context": asset_context,
            "priority_reasons": _compute_priority_reasons(item, asset_context, kev_map),
            "purl": build_purl(item.ecosystem, item.package_name, item.installed_version),
        }))

    return DependencyFindingListResponse(total=total, page=page, per_page=per_page, data=data)


def _fetch_asset_context_map(
    db: Session, repo_full_names: set[str],
) -> dict[str, RepoAssetContextOut]:
    """指定リポジトリ群の資産コンテキストをまとめて取得する（N+1クエリ回避）。

    Issue #131: DependencyFindingOut.asset_context に埋め込むため、一覧取得の
    たびにこのマップを1回のクエリで作り、Python側でrepo_full_nameをキーに
    引き当てる（1件ずつ問い合わせない）。
    """
    if not repo_full_names:
        return {}
    rows = (
        db.query(RepoAssetContext)
        .filter(RepoAssetContext.repo_full_name.in_(repo_full_names))
        .all()
    )
    return {row.repo_full_name: RepoAssetContextOut.model_validate(row) for row in rows}


def _fetch_kev_map(
    db: Session, items: list[DependencyFinding],
) -> dict[str, Vulnerability]:
    """指定した検知結果群のCVE ID群について、CISA KEV掲載レコードをまとめて取得する
    （N+1クエリ回避、Issue #135）。

    Returns:
        {cve_id: Vulnerability} の辞書（KEV未掲載のCVE IDは含まれない）
    """
    all_cve_ids = {cve_id for item in items for cve_id in item.cve_ids}
    if not all_cve_ids:
        return {}
    rows = db.query(Vulnerability).filter(Vulnerability.cve_id.in_(all_cve_ids)).all()
    return {row.cve_id: row for row in rows}


def _compute_priority_reasons(
    item: DependencyFinding,
    asset_context: RepoAssetContextOut | None,
    kev_map: dict[str, Vulnerability],
) -> list[str]:
    """優先度判定に寄与した要因を機械可読な理由コードのリストとして返す（Issue #135）。

    「脆弱性そのものの深刻度」に加え、CISA KEV掲載・EPSSスコア・到達可能性・
    資産コンテキスト（#131）を組み合わせて、対応の優先度を分析者が素早く
    判断できるようにする。各理由は独立した判定のため、複数該当してもよい。
    """
    reasons: list[str] = []

    matched_kev = [kev_map[cve_id] for cve_id in item.cve_ids if cve_id in kev_map]
    if matched_kev:
        reasons.append("kev_listed")
        if any(
            v.epss_score is not None and v.epss_score >= _EPSS_HIGH_THRESHOLD
            for v in matched_kev
        ):
            reasons.append("epss_high")

    if item.reachability == "reachable":
        reasons.append("reachable")
    if item.repo_visibility == "public":
        reasons.append("public_repo")
    if asset_context is not None:
        if asset_context.is_internet_facing:
            reasons.append("internet_facing_asset")
        if asset_context.is_production:
            reasons.append("production_asset")
        if asset_context.importance == "high":
            reasons.append("high_importance_asset")

    return reasons


@router.get(
    "/stats",
    response_model=DependencyFindingStatsResponse,
    summary="依存ライブラリ脆弱性の統計情報",
    description="未解決の検知結果について、リポジトリ別件数・重要度別件数を返す。",
)
def get_depscan_stats(
    db: Annotated[Session, Depends(get_db)],
    forced_owner: Annotated[str | None, Depends(_resolve_access)],
) -> DependencyFindingStatsResponse:
    """未解決の依存ライブラリ脆弱性を集計して返す。

    セッショントークン認証時は、ログイン中の GitHub ユーザー本人が所有する
    リポジトリのみに強制的に絞り込む。
    """
    base = db.query(DependencyFinding).filter(DependencyFinding.resolved_at.is_(None))
    if forced_owner is not None:
        base = base.filter(DependencyFinding.repo_full_name.like(f"{forced_owner}/%"))

    total = base.count()

    repo_rows = (
        base.with_entities(
            DependencyFinding.repo_full_name,
            func.count(DependencyFinding.id).label("cnt"),
        )
        .group_by(DependencyFinding.repo_full_name)
        .order_by(func.count(DependencyFinding.id).desc())
        .all()
    )
    repos = [RepoStat(repo_full_name=r[0], count=r[1]) for r in repo_rows]

    sev_rows = (
        base.with_entities(
            DependencyFinding.severity,
            func.count(DependencyFinding.id).label("cnt"),
        )
        .group_by(DependencyFinding.severity)
        .order_by(func.count(DependencyFinding.id).desc())
        .all()
    )
    severities = [SeverityStat(severity=r[0] or "N/A", count=r[1]) for r in sev_rows]

    logger.info("get_depscan_stats: total=%d, repos=%d", total, len(repos))
    return DependencyFindingStatsResponse(total=total, repos=repos, severities=severities)


@router.get(
    "/assets",
    response_model=RepoAssetContextListResponse,
    dependencies=[Security(require_public_api_key)],
    summary="リポジトリ資産コンテキスト一覧取得",
    description="手動設定済みの資産コンテキスト（本番デプロイ済みか・インターネット公開か・"
    "重要度）を全件返す（Issue #131）。設定されていないリポジトリは含まれない。",
)
def list_asset_contexts(
    db: Annotated[Session, Depends(get_db)],
) -> RepoAssetContextListResponse:
    """設定済みの資産コンテキストを全件返す。"""
    rows = db.query(RepoAssetContext).order_by(RepoAssetContext.repo_full_name).all()
    return RepoAssetContextListResponse(
        data=[RepoAssetContextOut.model_validate(row) for row in rows],
    )


@admin_router.put(
    "/admin/depscan/assets/{owner}/{repo}",
    response_model=RepoAssetContextOut,
    dependencies=[Security(require_api_key)],
    summary="リポジトリ資産コンテキストの設定",
    description="本番デプロイ済みか・インターネット公開か・資産重要度を手動設定する"
    "（Issue #131。X-API-KEY 必須）。既存設定があれば上書きする（Upsert）。",
)
def set_asset_context(
    owner: str, repo: str, body: RepoAssetContextIn, db: Annotated[Session, Depends(get_db)],
) -> RepoAssetContextOut:
    """指定リポジトリの資産コンテキストを設定（Upsert）する。"""
    repo_full_name = f"{owner}/{repo}"
    existing = (
        db.query(RepoAssetContext)
        .filter(RepoAssetContext.repo_full_name == repo_full_name)
        .first()
    )
    if existing is None:
        existing = RepoAssetContext(repo_full_name=repo_full_name)
        db.add(existing)
    existing.is_production = body.is_production
    existing.is_internet_facing = body.is_internet_facing
    existing.importance = body.importance
    db.commit()
    db.refresh(existing)

    logger.info(
        "set_asset_context: repo=%s, is_production=%s, is_internet_facing=%s, importance=%r",
        repo_full_name, body.is_production, body.is_internet_facing, body.importance,
    )
    return RepoAssetContextOut.model_validate(existing)


# SBOM形式ごとのメディアタイプ（各ツールがContent-Typeで形式を判別できるように、
# 標準JSONではなくSBOM専用のメディアタイプを明示する）
_SBOM_MEDIA_TYPES = {
    "cyclonedx": "application/vnd.cyclonedx+json",
    "spdx": "application/spdx+json",
}


@router.get(
    "/export",
    summary="DEPSCAN検知結果をSBOM形式でエクスポート",
    description="指定リポジトリの検知結果をCycloneDX 1.5またはSPDX 2.3形式でエクスポートする"
    "（Issue #133）。パッケージ識別にはpurl（Package URL）を使用する。SPDXはコア仕様に"
    "脆弱性を表現する概念が無いためパッケージ一覧のみを返す（脆弱性はCycloneDX形式か"
    "GET /api/depscan で確認する）。",
)
def export_depscan_sbom(
    db: Annotated[Session, Depends(get_db)],
    forced_owner: Annotated[str | None, Depends(_resolve_access)],
    repo: str = Query(..., description="対象リポジトリ（例: owner/repo）"),
    format: Literal["cyclonedx", "spdx"] = Query("cyclonedx", description="出力形式"),
    resolved: bool | None = Query(None, description="解決状態で絞り込み（未指定なら全件）"),
) -> Response:
    """指定リポジトリのDEPSCAN検知結果をSBOM形式でエクスポートする。"""
    if forced_owner is not None and not repo.startswith(f"{forced_owner}/"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only export repositories you own.",
        )

    query = db.query(DependencyFinding).filter(DependencyFinding.repo_full_name == repo)
    if resolved is not None:
        if resolved:
            query = query.filter(DependencyFinding.resolved_at.is_not(None))
        else:
            query = query.filter(DependencyFinding.resolved_at.is_(None))
    findings = query.all()

    sbom = build_spdx_sbom(repo, findings) if format == "spdx" else build_cyclonedx_sbom(
        repo, findings,
    )

    logger.info(
        "export_depscan_sbom: repo=%s, format=%s, resolved=%r, findings=%d",
        repo, format, resolved, len(findings),
    )
    return Response(content=json.dumps(sbom), media_type=_SBOM_MEDIA_TYPES[format])
