"""app.sla.report（対応状況の集計: 期限超過・MTTR）のテスト。"""
import os
from datetime import UTC, date, datetime, timedelta

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.depscan.filters import DepscanListFilter  # noqa: E402
from app.depscan.models import DependencyFinding  # noqa: E402
from app.kev.models import Vulnerability  # noqa: E402
from app.sla.policy import SlaPolicy  # noqa: E402
from app.sla.report import SlaItem, build_report  # noqa: E402

NOW = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)
POLICY = SlaPolicy(critical_days=7, high_days=30, medium_days=90, kev_days=7)


def _finding(*, repo="u/app", severity="HIGH", detected_days_ago, resolved_days_ago=None,
             osv_id="GHSA-x", pkg="pkg", cve_ids=None):
    return DependencyFinding(
        repo_full_name=repo, ecosystem="npm", package_name=pkg, installed_version="1.0.0",
        osv_id=osv_id, severity=severity, summary="s", fixed_versions=[],
        cve_ids=cve_ids or [], manifest_path="package-lock.json",
        detected_at=NOW - timedelta(days=detected_days_ago),
        resolved_at=(
            NOW - timedelta(days=resolved_days_ago) if resolved_days_ago is not None else None
        ),
    )


def _flt(**kwargs):
    base = {"repo": None, "owner": None, "ecosystem": None, "severity": None,
            "resolved": None, "operating": "all"}
    base.update(kwargs)
    return DepscanListFilter(**base)


def _report(db, findings, *, policy=POLICY, window_days=90, flt=None):
    db.add_all(findings)
    db.commit()
    return build_report(db, flt or _flt(), policy, window_days=window_days, now=NOW)


class TestOverdue:
    def test_open_finding_past_its_deadline_is_overdue(self, db_session):
        # HIGH の期限は 30 日。40 日前の検知は、10 日超過
        report = _report(db_session, [_finding(detected_days_ago=40)])

        assert report.summary.overdue == 1
        item = report.overdue[0]
        assert item.overdue_days == 10
        assert item.deadline_days == 30
        assert item.due_at == (NOW - timedelta(days=10)).isoformat()

    def test_finding_within_its_deadline_is_not_overdue(self, db_session):
        report = _report(db_session, [_finding(detected_days_ago=20)])

        assert report.summary.open_with_deadline == 1
        assert report.summary.overdue == 0
        assert report.overdue == []

    def test_low_and_unknown_severity_have_no_deadline(self, db_session):
        report = _report(db_session, [
            _finding(severity="LOW", detected_days_ago=400, osv_id="a"),
            _finding(severity=None, detected_days_ago=400, osv_id="b"),
        ])

        assert report.summary.open_with_deadline == 0
        assert report.summary.overdue == 0

    def test_kev_listed_finding_gets_the_shorter_deadline(self, db_session):
        db_session.add(Vulnerability(
            cve_id="CVE-2026-1", vendor_project="V", product="P", vulnerability_name="n",
            description="d", required_action=None, date_added=date(2026, 10, 1),
        ))
        # MEDIUM（90日）でも、KEV 掲載なら 7 日。10 日前の検知は 3 日超過
        report = _report(db_session, [
            _finding(severity="MEDIUM", detected_days_ago=10, cve_ids=["CVE-2026-1"]),
        ])

        item = report.overdue[0]
        assert item.is_kev is True
        assert item.deadline_days == 7
        assert item.overdue_days == 3

    def test_malicious_package_uses_the_critical_deadline(self, db_session):
        report = _report(db_session, [
            _finding(severity="CRITICAL", detected_days_ago=9, osv_id="MAL-2026-1"),
        ])

        item = report.overdue[0]
        assert item.is_malicious is True
        assert item.deadline_days == 7

    def test_resolved_finding_is_never_overdue(self, db_session):
        report = _report(db_session, [
            _finding(detected_days_ago=100, resolved_days_ago=1),
        ])

        assert report.summary.overdue == 0

    def test_overdue_sorted_by_days_overdue_descending(self, db_session):
        report = _report(db_session, [
            _finding(detected_days_ago=40, osv_id="a", pkg="small"),
            _finding(detected_days_ago=80, osv_id="b", pkg="big"),
        ])

        assert [i.package_name for i in report.overdue] == ["big", "small"]


class TestMttr:
    def test_mttr_is_the_mean_days_from_detection_to_resolution(self, db_session):
        report = _report(db_session, [
            _finding(detected_days_ago=20, resolved_days_ago=10, osv_id="a"),  # 10日
            _finding(detected_days_ago=30, resolved_days_ago=10, osv_id="b"),  # 20日
        ])

        assert report.summary.resolved == 2
        assert report.summary.mttr_days == 15.0

    def test_mttr_is_none_when_nothing_was_resolved(self, db_session):
        assert _report(db_session, [_finding(detected_days_ago=1)]).summary.mttr_days is None

    def test_resolved_before_the_window_is_not_counted(self, db_session):
        report = _report(db_session, [
            _finding(detected_days_ago=200, resolved_days_ago=100, osv_id="old"),
            _finding(detected_days_ago=20, resolved_days_ago=10, osv_id="new"),
        ], window_days=90)

        assert report.summary.resolved == 1
        assert report.summary.mttr_days == 10.0

    def test_by_severity_in_severity_order_with_deadlines(self, db_session):
        report = _report(db_session, [
            _finding(severity="MEDIUM", detected_days_ago=5, resolved_days_ago=1, osv_id="m"),
            _finding(severity="CRITICAL", detected_days_ago=20, osv_id="c"),
            _finding(severity="LOW", detected_days_ago=3, osv_id="l"),
            _finding(severity=None, detected_days_ago=3, osv_id="n"),
        ])

        assert [s.severity for s in report.by_severity] == ["CRITICAL", "MEDIUM", "LOW", "N/A"]
        critical = report.by_severity[0]
        assert (critical.deadline_days, critical.open, critical.overdue) == (7, 1, 1)
        medium = report.by_severity[1]
        assert (medium.open, medium.resolved, medium.mttr_days) == (0, 1, 4.0)
        assert report.by_severity[2].deadline_days is None


class TestByRepo:
    def test_repos_sorted_by_overdue_then_open(self, db_session):
        report = _report(db_session, [
            _finding(repo="u/quiet", detected_days_ago=1, osv_id="q"),
            _finding(repo="u/late", detected_days_ago=50, osv_id="l1"),
            _finding(repo="u/late", detected_days_ago=60, osv_id="l2"),
            _finding(repo="u/mid", detected_days_ago=40, osv_id="m"),
        ])

        assert [(r.repo_full_name, r.overdue) for r in report.by_repo] == [
            ("u/late", 2), ("u/mid", 1), ("u/quiet", 0),
        ]


class TestExclusionAndScope:
    def test_excluded_osv_ids_are_left_out_of_every_count(self, db_session):
        policy = SlaPolicy(
            critical_days=7, high_days=30, medium_days=90, kev_days=7,
            excluded_osv_ids=frozenset({"GHSA-accepted"}),
        )
        report = _report(db_session, [
            _finding(detected_days_ago=100, osv_id="GHSA-accepted"),
            _finding(detected_days_ago=100, osv_id="GHSA-other"),
        ], policy=policy)

        assert report.summary.overdue == 1
        assert report.overdue[0].osv_id == "GHSA-other"
        assert report.policy.excluded_osv_ids == ["GHSA-accepted"]

    def test_owner_filter_limits_to_that_owners_repos(self, db_session):
        report = _report(db_session, [
            _finding(repo="alice/a", detected_days_ago=50, osv_id="a"),
            _finding(repo="bob/b", detected_days_ago=50, osv_id="b"),
        ], flt=_flt(owner="alice"))

        assert [i.repo_full_name for i in report.overdue] == ["alice/a"]

    def test_empty_database_gives_an_empty_report(self, db_session):
        report = build_report(db_session, _flt(), POLICY, window_days=90, now=NOW)

        assert report.summary.model_dump() == {
            "open_with_deadline": 0, "overdue": 0, "resolved": 0, "mttr_days": None,
        }
        assert report.by_severity == [] and report.by_repo == [] and report.overdue == []


class TestSlaItem:
    def _item(self, **kwargs):
        base = {
            "repo_full_name": "u/r", "package_name": "p", "installed_version": "1",
            "osv_id": "x", "severity": "HIGH", "is_kev": False,
            "detected_at": NOW - timedelta(days=40), "resolved_at": None, "deadline_days": 30,
        }
        base.update(kwargs)
        return SlaItem(**base)

    def test_due_at_is_detection_plus_deadline(self):
        assert self._item().due_at == NOW - timedelta(days=10)

    def test_no_deadline_means_no_due_date_and_never_overdue(self):
        item = self._item(deadline_days=None)

        assert item.due_at is None
        assert item.is_overdue(NOW) is False
        assert item.overdue_days(NOW) == 0

    def test_naive_datetimes_from_the_database_are_treated_as_utc(self, db_session):
        # SQLite は tz を保持しないため、naive で戻っても集計が壊れない
        db_session.add(_finding(detected_days_ago=40))
        db_session.commit()
        db_session.expire_all()

        report = build_report(db_session, _flt(), POLICY, window_days=90, now=NOW)

        assert report.summary.overdue == 1
