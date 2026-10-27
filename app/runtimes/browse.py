"""使っている言語・実行環境の閲覧（RUNTIME。リポジトリごと・状態つき）。

状態（`status.evaluate`）は、保存せず、閲覧のたびに「使っている版」と「リリース情報」から
求める。サポート期限が日々近づくため、保存すると古くなるのと、リリース情報の更新が
すぐに反映されるため。件数は、リポジトリ数 × 数件と少ないので、条件に合う行を全て取り、
状態を求めてから絞り込む。
"""
from datetime import date
from typing import Any

from sqlalchemy.orm import Query, Session

from app.core.operating_status import OperatingStatus, apply_operating_status
from app.runtimes.models import RepoRuntime, RuntimeRelease
from app.runtimes.status import NEEDS_ACTION_STATES, RuntimeStatus, evaluate

# 並び順: 対応が急ぐものを先頭にする
_STATE_ORDER = {
    "eol": 0, "eol_soon": 1, "update_available": 2, "unknown": 3, "latest": 4, "reference": 5,
}


def _restrict_to_owner(query: Query[Any], forced_owner: str | None) -> Query[Any]:
    """セッション認証時は、そのオーナーのリポジトリのみに強制的に絞る。"""
    if forced_owner is None:
        return query
    # `_` を含むオーナー名でも他のオーナーに一致しないよう、LIKE ではなく前方一致で絞る
    return query.filter(RepoRuntime.repo_full_name.startswith(f"{forced_owner}/", autoescape=True))


def list_runtimes(
    db: Session,
    *,
    today: date,
    forced_owner: str | None = None,
    repo: str | None = None,
    runtime: str | None = None,
    needs_action: bool = False,
    operating: OperatingStatus = "all",
) -> list[tuple[RepoRuntime, RuntimeStatus]]:
    """使っている言語・実行環境を、状態つきで返す（対応が急ぐものが先頭）。

    Args:
        forced_owner: 指定した場合、そのオーナーのリポジトリのみに強制的に絞る
        repo: リポジトリ（完全一致。例: owner/repo）
        runtime: 言語・実行環境（python / nodejs / flutter / dart）
        needs_action: True なら、対応が必要な状態（期限切れ・期限間近・更新あり）のみ
        operating: 運用状態（active=運用中 / inactive=運用停止中 / all）
    """
    query = _restrict_to_owner(db.query(RepoRuntime), forced_owner)
    if repo:
        query = query.filter(RepoRuntime.repo_full_name == repo)
    if runtime:
        query = query.filter(RepoRuntime.runtime == runtime)
    query = apply_operating_status(query, RepoRuntime.repo_full_name, operating)

    releases = db.query(RuntimeRelease).all()
    rows = [
        (row, evaluate(row.runtime, row.cycle, pinned=row.pinned, releases=releases, today=today))
        for row in query.all()
    ]
    if needs_action:
        rows = [(row, st) for row, st in rows if st.state in NEEDS_ACTION_STATES]
    rows.sort(key=lambda item: (
        _STATE_ORDER[item[1].state], item[0].repo_full_name, item[0].runtime, item[0].cycle,
    ))
    return rows


def summarize_repos(
    db: Session,
    *,
    today: date,
    forced_owner: str | None = None,
    operating: OperatingStatus = "all",
) -> list[tuple[str, int, int]]:
    """リポジトリごとの、(リポジトリ名, 検出した数, うち対応が必要な数) を返す。

    対応が必要な数が多いリポジトリが先頭（同数ならリポジトリ名の順）。
    """
    totals: dict[str, list[int]] = {}
    for row, st in list_runtimes(
        db, today=today, forced_owner=forced_owner, operating=operating,
    ):
        counts = totals.setdefault(row.repo_full_name, [0, 0])
        counts[0] += 1
        if st.state in NEEDS_ACTION_STATES:
            counts[1] += 1
    return sorted(
        ((repo, c[0], c[1]) for repo, c in totals.items()),
        key=lambda item: (-item[2], item[0]),
    )
