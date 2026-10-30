"""検知（DEPSCAN）から、対応状況（期限超過・MTTR）のレポートを組み立てる。"""
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from statistics import fmean

from sqlalchemy.orm import Session

from app.core.osv_client import is_malicious_advisory
from app.depscan.filters import DepscanListFilter
from app.depscan.models import DependencyFinding
from app.depscan.priority import fetch_kev_map
from app.finding_exceptions.matching import exception_map, key_of_finding
from app.finding_exceptions.models import KIND_DEPENDENCY
from app.sla.policy import SlaPolicy
from app.sla.schemas import (
    SlaOverdueItem,
    SlaPolicyOut,
    SlaReportOut,
    SlaRepoStat,
    SlaSeverityStat,
    SlaSummary,
)

# 重要度の並び順（深刻な順）。ここに無い値（不明）は最後にまとめる
_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_UNKNOWN_SEVERITY = "N/A"


def _as_utc(value: datetime) -> datetime:
    """DB から読んだ日時を UTC の aware にそろえる（SQLite は tz を保持しない）。"""
    return value if value.tzinfo else value.replace(tzinfo=UTC)


@dataclass(frozen=True)
class SlaItem:
    """期限の判定に必要な項目だけを持つ、1件の検知。"""

    repo_full_name: str
    package_name: str
    installed_version: str
    osv_id: str
    severity: str
    is_kev: bool
    detected_at: datetime
    resolved_at: datetime | None
    deadline_days: int | None

    @property
    def due_at(self) -> datetime | None:
        """期限日時。期限が無い検知は None。"""
        if self.deadline_days is None:
            return None
        return self.detected_at + timedelta(days=self.deadline_days)

    def overdue_days(self, now: datetime) -> int:
        """期限を超えた日数（未解決のみ。期限内・期限なし・解決済みは 0）。"""
        due = self.due_at
        if self.resolved_at is not None or due is None or now <= due:
            return 0
        return max((now - due).days, 0)

    def is_overdue(self, now: datetime) -> bool:
        due = self.due_at
        return self.resolved_at is None and due is not None and now > due

    def days_to_resolve(self) -> float | None:
        """検知から解決までの日数（未解決は None）。"""
        if self.resolved_at is None:
            return None
        return (self.resolved_at - self.detected_at).total_seconds() / 86400


def _mttr(items: list[SlaItem]) -> float | None:
    """解決済みの検知の、平均対応日数（小数第1位）。解決が0件なら None。"""
    days = [d for item in items if (d := item.days_to_resolve()) is not None]
    return round(fmean(days), 1) if days else None


def _to_items(
    rows: list[DependencyFinding], policy: SlaPolicy,
    kev_cve_ids: set[str], excepted: set[tuple[str, str]],
) -> list[SlaItem]:
    """ORM の検知を、期限つきの `SlaItem` にする。

    例外（受容など。`excepted` は (リポジトリ, 同一性キー)）にした未解決の検知は含めない
    （対応が要らないため、期限超過に数えない。解決済みは、対応にかかった日数として残す）。
    """
    items = []
    for row in rows:
        if row.resolved_at is None and (
            row.repo_full_name, key_of_finding(KIND_DEPENDENCY, row),
        ) in excepted:
            continue
        is_kev = any(cve in kev_cve_ids for cve in row.cve_ids)
        items.append(SlaItem(
            repo_full_name=row.repo_full_name,
            package_name=row.package_name,
            installed_version=row.installed_version,
            osv_id=row.osv_id,
            severity=(row.severity or _UNKNOWN_SEVERITY).upper(),
            is_kev=is_kev,
            detected_at=_as_utc(row.detected_at),
            resolved_at=_as_utc(row.resolved_at) if row.resolved_at else None,
            deadline_days=policy.deadline_days(row.severity, is_kev=is_kev),
        ))
    return items


def _severity_stats(
    items: list[SlaItem], policy: SlaPolicy, now: datetime,
) -> list[SlaSeverityStat]:
    """重要度別（深刻な順）の件数と MTTR。"""
    severities = sorted(
        {item.severity for item in items},
        key=lambda s: _SEVERITY_ORDER.index(s) if s in _SEVERITY_ORDER else len(_SEVERITY_ORDER),
    )
    stats = []
    for severity in severities:
        group = [i for i in items if i.severity == severity]
        stats.append(SlaSeverityStat(
            severity=severity,
            deadline_days=policy.days_for_severity(severity),
            open=sum(1 for i in group if i.resolved_at is None),
            overdue=sum(1 for i in group if i.is_overdue(now)),
            resolved=sum(1 for i in group if i.resolved_at is not None),
            mttr_days=_mttr(group),
        ))
    return stats


def _repo_stats(items: list[SlaItem], now: datetime) -> list[SlaRepoStat]:
    """リポジトリ別の件数と MTTR（期限超過が多い順、同数なら未解決が多い順）。"""
    by_repo: dict[str, list[SlaItem]] = {}
    for item in items:
        by_repo.setdefault(item.repo_full_name, []).append(item)
    stats = [
        SlaRepoStat(
            repo_full_name=repo,
            open=sum(1 for i in group if i.resolved_at is None),
            overdue=sum(1 for i in group if i.is_overdue(now)),
            resolved=sum(1 for i in group if i.resolved_at is not None),
            mttr_days=_mttr(group),
        )
        for repo, group in by_repo.items()
    ]
    return sorted(stats, key=lambda s: (-s.overdue, -s.open, s.repo_full_name))


def _overdue_items(items: list[SlaItem], now: datetime) -> list[SlaOverdueItem]:
    """期限を超えている検知（超過日数が多い順）。"""
    overdue = [i for i in items if i.is_overdue(now)]
    overdue.sort(key=lambda i: (-i.overdue_days(now), i.repo_full_name, i.package_name))
    return [
        SlaOverdueItem(
            repo_full_name=i.repo_full_name,
            package_name=i.package_name,
            installed_version=i.installed_version,
            osv_id=i.osv_id,
            severity=None if i.severity == _UNKNOWN_SEVERITY else i.severity,
            is_kev=i.is_kev,
            is_malicious=is_malicious_advisory(i.osv_id),
            detected_at=i.detected_at.isoformat(),
            # overdue の検知は期限を必ず持つ（is_overdue が deadline の有無を見ている）
            deadline_days=i.deadline_days or 0,
            due_at=(i.due_at or i.detected_at).isoformat(),
            overdue_days=i.overdue_days(now),
        )
        for i in overdue
    ]


def _excepted_osv_ids(
    open_rows: list[DependencyFinding], excepted: set[tuple[str, str]],
) -> set[str]:
    """期限の計算から外している（例外にした未解決の）検知の OSV ID。"""
    return {
        row.osv_id for row in open_rows
        if (row.repo_full_name, key_of_finding(KIND_DEPENDENCY, row)) in excepted
    }


def build_report(
    db: Session,
    flt: DepscanListFilter,
    policy: SlaPolicy,
    *,
    window_days: int,
    now: datetime | None = None,
) -> SlaReportOut:
    """対応状況のレポートを作る。

    未解決の検知すべてと、直近 `window_days` 日以内に解決した検知を対象にする
    （MTTR を直近の傾向にするため。古い解決済みは含めない）。
    `flt` はオーナー・運用状態・リポジトリの絞り込みで、セッション認証時は本人所有に絞った
    ものを渡す。`resolved` の指定は、このレポート自身が決めるため使わない。
    """
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=window_days)

    base = flt.apply(db.query(DependencyFinding))
    open_rows = base.filter(DependencyFinding.resolved_at.is_(None)).all()
    resolved_rows = base.filter(DependencyFinding.resolved_at >= cutoff).all()
    rows = [*open_rows, *resolved_rows]

    kev_cve_ids = set(fetch_kev_map(db, rows))
    excepted = set(exception_map(db, KIND_DEPENDENCY, {r.repo_full_name for r in rows}))
    items = _to_items(rows, policy, kev_cve_ids, excepted)

    summary = SlaSummary(
        open_with_deadline=sum(
            1 for i in items if i.resolved_at is None and i.deadline_days is not None
        ),
        overdue=sum(1 for i in items if i.is_overdue(now)),
        resolved=sum(1 for i in items if i.resolved_at is not None),
        mttr_days=_mttr(items),
    )
    return SlaReportOut(
        generated_at=now.isoformat(),
        mttr_window_days=window_days,
        policy=SlaPolicyOut(
            critical_days=policy.critical_days,
            high_days=policy.high_days,
            medium_days=policy.medium_days,
            kev_days=policy.kev_days,
            excluded_osv_ids=sorted(_excepted_osv_ids(open_rows, excepted)),
        ),
        summary=summary,
        by_severity=_severity_stats(items, policy, now),
        by_repo=_repo_stats(items, now),
        overdue=_overdue_items(items, now),
    )
