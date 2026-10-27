"""使っている言語・実行環境の閲覧（RUNTIME。リポジトリごと・状態つき）。

状態（`status.evaluate`）は、保存せず、閲覧のたびに「使っている版」と「リリース情報」から
求める。サポート期限が日々近づくため、保存すると古くなるのと、リリース情報の更新が
すぐに反映されるため。件数は、リポジトリ数 × 数件と少ないので、条件に合う行を全て取り、
状態を求めてから絞り込む。
"""
from dataclasses import replace
from datetime import date

from sqlalchemy.orm import Session

from app.runtimes.filters import RuntimeFilter
from app.runtimes.models import RepoRuntime, RuntimeRelease
from app.runtimes.status import NEEDS_ACTION_STATES, RuntimeStatus, evaluate

# 並び順: 対応が急ぐものを先頭にする
_STATE_ORDER = {
    "eol": 0, "eol_soon": 1, "update_available": 2, "unknown": 3, "latest": 4, "reference": 5,
}


def list_runtimes(
    db: Session, flt: RuntimeFilter, *, today: date,
) -> list[tuple[RepoRuntime, RuntimeStatus]]:
    """使っている言語・実行環境を、状態つきで返す（対応が急ぐものが先頭）。

    Args:
        flt: 絞り込み条件（所有者の制限・運用状態・対応が必要なものだけ、を含む）
        today: 状態（サポート期限までの日数）を求める基準の日
    """
    query = flt.apply(db.query(RepoRuntime))

    releases = db.query(RuntimeRelease).all()
    rows = [
        (row, evaluate(row.runtime, row.cycle, pinned=row.pinned, releases=releases, today=today))
        for row in query.all()
    ]
    if flt.needs_action:
        rows = [(row, st) for row, st in rows if st.state in NEEDS_ACTION_STATES]
    rows.sort(key=lambda item: (
        _STATE_ORDER[item[1].state], item[0].repo_full_name, item[0].runtime, item[0].cycle,
    ))
    return rows


def summarize_repos(
    db: Session, flt: RuntimeFilter, *, today: date,
) -> list[tuple[str, int, int]]:
    """リポジトリごとの、(リポジトリ名, 検出した数, うち対応が必要な数) を返す。

    対応が必要な数が多いリポジトリが先頭（同数ならリポジトリ名の順）。件数は、条件に合う
    全ての行を数える（`needs_action` は、「うち対応が必要な数」を別に数えるため、使わない）。
    """
    totals: dict[str, list[int]] = {}
    for row, st in list_runtimes(db, replace(flt, needs_action=False), today=today):
        counts = totals.setdefault(row.repo_full_name, [0, 0])
        counts[0] += 1
        if st.state in NEEDS_ACTION_STATES:
            counts[1] += 1
    return sorted(
        ((repo, c[0], c[1]) for repo, c in totals.items()),
        key=lambda item: (-item[2], item[0]),
    )
