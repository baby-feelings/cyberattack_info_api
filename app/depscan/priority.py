"""DEPSCAN の説明可能な優先度推薦ロジック（Issue #135）。

「なぜその脆弱性の優先度が高いと判断されたか」を機械可読な理由コード配列として
提示するための純粋なビジネスロジックを、HTTP ルーティング（app.depscan.router）から
分離したモジュール（Separation of Concerns）。KEV突合・資産コンテキスト取得の
N+1クエリ回避ヘルパーもここに置く。
"""
from sqlalchemy.orm import Session

from app.depscan.models import DependencyFinding, RepoAssetContext
from app.depscan.schemas import RepoAssetContextOut
from app.kev.models import Vulnerability

# EPSSスコアがこの値以上なら"epss_high"理由を付与する（Issue #135）。
# FIRSTのEPSS運用ガイドでは明確な閾値は定義されていないが、0.5は一般的に
# 「悪用確率が偶然を上回る」目安として引用される値
_EPSS_HIGH_THRESHOLD = 0.5


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
