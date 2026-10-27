"""依存パッケージの横断検索・閲覧（DEPSCAN。「どのリポジトリが、そのパッケージのどの版を使っているか」）。

新しい脆弱性が公表されたときの影響範囲の確認や、リポジトリごとに使っている依存の一覧に使う。
検索対象は `RepoDependency`（依存の全量）で、脆弱性の有無にかかわらず、使っている依存を引く。
各行には、その版に未解決の検知が何件あるかを付ける（検知が無い版と、対応が必要な版を
一目で区別できるようにするため）。
"""
from typing import Any

from sqlalchemy import case, exists, func
from sqlalchemy.orm import Session

from app.core.operating_status import OperatingStatus, apply_operating_status
from app.core.owner_scope import restrict_to_owner
from app.depscan.models import DependencyFinding, RepoDependency

DependencyKey = tuple[str, str, str, str]


def _has_open_finding() -> Any:
    """その依存（リポジトリ・エコシステム・パッケージ・版が一致）に、未解決の検知がある、という条件。"""
    return exists().where(
        DependencyFinding.resolved_at.is_(None),
        DependencyFinding.repo_full_name == RepoDependency.repo_full_name,
        DependencyFinding.ecosystem == RepoDependency.ecosystem,
        DependencyFinding.package_name == RepoDependency.package_name,
        DependencyFinding.installed_version == RepoDependency.version,
    )


def search_dependencies(
    db: Session,
    *,
    page: int,
    per_page: int,
    forced_owner: str | None = None,
    package: str | None = None,
    version: str | None = None,
    ecosystem: str | None = None,
    repo: str | None = None,
    vulnerable: bool = False,
    operating: OperatingStatus = "all",
) -> tuple[int, list[tuple[RepoDependency, int]]]:
    """条件に合う依存を返す（(総件数, [(依存, 未解決の検知件数)])）。

    Args:
        forced_owner: 指定した場合、そのオーナーのリポジトリのみに強制的に絞る
            （セッション認証時に、本人所有のリポジトリ以外を返さないため）
        package: パッケージ名（部分一致・大文字小文字を区別しない）
        version: バージョン（完全一致）
        ecosystem: エコシステム（完全一致。例: PyPI / npm / Pub）
        repo: リポジトリ（完全一致。例: owner/repo）
        vulnerable: True なら、未解決の検知がある依存だけ
        operating: 運用状態（運用中／運用停止中／すべて）
    """
    query = apply_operating_status(
        restrict_to_owner(db.query(RepoDependency), RepoDependency.repo_full_name, forced_owner),
        RepoDependency.repo_full_name, operating,
    )
    if package:
        query = query.filter(RepoDependency.package_name.icontains(package, autoescape=True))
    if version:
        query = query.filter(RepoDependency.version == version)
    if ecosystem:
        query = query.filter(RepoDependency.ecosystem == ecosystem)
    if repo:
        query = query.filter(RepoDependency.repo_full_name == repo)
    if vulnerable:
        query = query.filter(_has_open_finding())

    total = query.count()
    rows = (
        query.order_by(
            RepoDependency.repo_full_name, RepoDependency.ecosystem,
            RepoDependency.package_name, RepoDependency.version,
            RepoDependency.manifest_path,
        )
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    open_counts = _open_vulnerability_counts(db, rows)
    return total, [
        (row, open_counts.get(
            (row.repo_full_name, row.ecosystem, row.package_name, row.version), 0,
        ))
        for row in rows
    ]


def summarize_repos(
    db: Session, *, forced_owner: str | None = None, operating: OperatingStatus = "all",
) -> list[tuple[str, int, int]]:
    """リポジトリごとの、使っている依存の数と、未解決の検知がある依存の数を返す。

    戻り値は (リポジトリ, 依存の数, うち未解決の検知がある依存の数) で、対応が必要な
    リポジトリ（検知がある依存が多い順）を先に、同数ならリポジトリ名順に並べる。
    """
    vulnerable_count = func.sum(case((_has_open_finding(), 1), else_=0))
    base = db.query(
        RepoDependency.repo_full_name, func.count(RepoDependency.id), vulnerable_count,
    )
    query = apply_operating_status(
        restrict_to_owner(base, RepoDependency.repo_full_name, forced_owner),
        RepoDependency.repo_full_name, operating,
    ).group_by(RepoDependency.repo_full_name)
    rows = [(repo, int(total), int(vulnerable or 0)) for repo, total, vulnerable in query.all()]
    return sorted(rows, key=lambda r: (-r[2], r[0]))


def _open_vulnerability_counts(
    db: Session, rows: list[RepoDependency],
) -> dict[DependencyKey, int]:
    """ページ内の依存ごとの、未解決の検知件数を返す（検知が無い依存はキー自体が無い）。"""
    if not rows:
        return {}
    findings = db.query(
        DependencyFinding.repo_full_name, DependencyFinding.ecosystem,
        DependencyFinding.package_name, DependencyFinding.installed_version,
        func.count(DependencyFinding.id),
    ).filter(
        DependencyFinding.resolved_at.is_(None),
        DependencyFinding.repo_full_name.in_({r.repo_full_name for r in rows}),
        DependencyFinding.package_name.in_({r.package_name for r in rows}),
    ).group_by(
        DependencyFinding.repo_full_name, DependencyFinding.ecosystem,
        DependencyFinding.package_name, DependencyFinding.installed_version,
    ).all()
    return {(repo, eco, name, ver): count for repo, eco, name, ver, count in findings}
