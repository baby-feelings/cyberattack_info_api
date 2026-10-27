"""言語・実行環境のバージョンの通知の判定と、送信済みの記録（RUNTIME）。

毎日の実行（`crawler`）の終わりに呼ばれ、**変化があったときだけ**、管理者の Slack に知らせる。
毎日同じ内容を送ると、見なくなるため。通知は、言語・系列ごとの、次の3種類。

- `new_release`: 新しい系列が公開された（公開から `NEW_RELEASE_WINDOW_DAYS` 日以内）
- `eol_soon`: 使っている系列のサポート終了が、`EOL_SOON_DAYS` 日以内になった
- `eol`: 使っている系列のサポートが終了した

`eol_soon`・`eol` は、運用中のアプリが、版を固定して使っているものだけが対象（下限の指定は、
実際に動いている版とは限らないため）。`new_release` は、その言語を使うアプリがあるときだけ。

送った通知は `runtime_alerts` に記録し、同じ通知を二重に送らない。**最初の実行は、既存の状況を
記録するだけで、通知しない**（導入した日に、これまでの全ての系列の通知が、一度に届かないため）。
"""
import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.core.notifications.runtime_alerts import notify_runtime_alerts
from app.runtimes.browse import list_runtimes
from app.runtimes.detector import RUNTIME_LABELS
from app.runtimes.filters import RuntimeFilter
from app.runtimes.models import RuntimeAlert, RuntimeRelease

logger = logging.getLogger(__name__)

# 公開から、この日数以内の系列を「新しい版」として通知する（古い系列が、後から取得元に
# 載っても、新しい版として通知しないため）
NEW_RELEASE_WINDOW_DAYS = 90

# 最初の実行（既存の状況を記録だけして、通知しなかった）の印となる記録のキー
INITIALIZED_KEY = "initialized"


@dataclass(frozen=True)
class RuntimeAlertItem:
    """通知1件（言語・系列ごとの出来事）。"""

    kind: str  # new_release / eol_soon / eol
    runtime: str
    cycle: str
    latest_version: str
    eol_date: date | None
    days_to_eol: int | None
    repos: tuple[str, ...]  # 使っている（運用中の）アプリ

    @property
    def key(self) -> str:
        """送信済みかを見分けるキー（例: `eol_soon:python:3.11`）。"""
        return f"{self.kind}:{self.runtime}:{self.cycle}"

    def as_dict(self) -> dict[str, Any]:
        """通知の本文を作る側（`core.notifications`）へ渡す辞書。core は、この型を知らない。"""
        return {
            "kind": self.kind,
            "runtime_label": RUNTIME_LABELS.get(self.runtime, self.runtime),
            "cycle": self.cycle,
            "latest_version": self.latest_version,
            "eol_date": self.eol_date.isoformat() if self.eol_date else None,
            "days_to_eol": self.days_to_eol,
            "repos": list(self.repos),
        }


def find_alerts(db: Session, today: date) -> list[RuntimeAlertItem]:
    """いま通知の対象になりうる出来事を、全て求める（送信済みかは、ここでは見ない）。"""
    releases = {(r.runtime, r.cycle): r for r in db.query(RuntimeRelease).all()}

    # 運用中のアプリが使っている、(言語, 系列) → アプリの一覧（版を固定しているものは別に数える）
    pinned_repos: dict[tuple[str, str], set[str]] = defaultdict(set)
    using_runtime: dict[str, set[str]] = defaultdict(set)
    states: dict[tuple[str, str], str] = {}
    for row, status in list_runtimes(db, RuntimeFilter(operating="active"), today=today):
        using_runtime[row.runtime].add(row.repo_full_name)
        if row.pinned:
            pinned_repos[(row.runtime, row.cycle)].add(row.repo_full_name)
            states[(row.runtime, row.cycle)] = status.state

    alerts: list[RuntimeAlertItem] = []

    # サポート終了・サポート終了が近い（使っている系列ごと）
    for (runtime, cycle), repos in pinned_repos.items():
        state = states[(runtime, cycle)]
        release = releases.get((runtime, cycle))
        if state not in ("eol", "eol_soon") or release is None:
            continue
        days = (release.eol_date - today).days if release.eol_date else None
        alerts.append(RuntimeAlertItem(
            kind=state, runtime=runtime, cycle=cycle, latest_version=release.latest_version,
            eol_date=release.eol_date, days_to_eol=days, repos=tuple(sorted(repos)),
        ))

    # 新しい系列の公開（その言語を使うアプリがあるときだけ）
    window_start = today - timedelta(days=NEW_RELEASE_WINDOW_DAYS)
    for (runtime, cycle), release in releases.items():
        # `.get` は、無ければ None を返すため、型が `set | None` になる。defaultdict の添字は、
        # 参照しただけで空の集合を作ってしまうため、`in` で確かめてから読む
        if runtime not in using_runtime or release.is_eol or release.release_date is None:
            continue
        repos = using_runtime[runtime]
        if release.release_date >= window_start:
            alerts.append(RuntimeAlertItem(
                kind="new_release", runtime=runtime, cycle=cycle,
                latest_version=release.latest_version, eol_date=release.eol_date,
                days_to_eol=None, repos=tuple(sorted(repos)),
            ))
    return sorted(alerts, key=lambda a: (a.kind, a.runtime, a.cycle))


def _sent_keys(db: Session) -> set[str]:
    return {row.alert_key for row in db.query(RuntimeAlert).all()}


def _record(db: Session, keys: list[str]) -> None:
    for key in keys:
        db.add(RuntimeAlert(alert_key=key))
    db.commit()


def send_runtime_alerts(today: date | None = None) -> int:
    """通知すべき出来事を送り、送ったものを記録する。送った件数を返す。

    - 最初の実行は、既存の状況を記録するだけで、通知しない（0 を返す）
    - 送信に失敗したものは、記録しない（翌日の実行で、もう一度送る）
    """
    today = today or datetime.now(UTC).date()
    with SessionLocal() as db:
        alerts = find_alerts(db, today)
        sent = _sent_keys(db)

        if INITIALIZED_KEY not in sent:
            _record(db, [INITIALIZED_KEY, *(a.key for a in alerts)])
            logger.info(
                "RUNTIME alerts: initialized with %d existing alerts (not sent)", len(alerts),
            )
            return 0

        unsent = [a for a in alerts if a.key not in sent]
        if not unsent:
            return 0
        if not notify_runtime_alerts([a.as_dict() for a in unsent]):
            logger.warning("RUNTIME alerts: failed to send %d alerts, will retry", len(unsent))
            return 0
        _record(db, [a.key for a in unsent])
        logger.info("RUNTIME alerts: sent %d alerts", len(unsent))
        return len(unsent)
