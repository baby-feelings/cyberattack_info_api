"""app.finding_exceptions の照合（matching）と永続化（repository）のテスト。"""
import os
from datetime import UTC, datetime, timedelta

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.codescan.models import CodeFinding  # noqa: E402
from app.depscan.models import DependencyFinding  # noqa: E402
from app.finding_exceptions.matching import (  # noqa: E402
    active_exceptions,
    code_key,
    dependency_key,
    drop_excepted,
    exception_map,
    finding_exists,
    findings_for,
    key_of_finding,
    not_excepted,
    snapshot_of,
)
from app.finding_exceptions.models import FindingException  # noqa: E402
from app.finding_exceptions.repository import FindingExceptionRepository  # noqa: E402

NOW = datetime.now(UTC)


def _dep(repo="u/app", pkg="lodash", osv="GHSA-1", resolved=False, fixed=None):
    return DependencyFinding(
        repo_full_name=repo, ecosystem="npm", package_name=pkg, installed_version="1.0.0",
        osv_id=osv, severity="HIGH", summary="s", fixed_versions=fixed or [], cve_ids=[],
        manifest_path="package-lock.json", detected_at=NOW,
        resolved_at=NOW if resolved else None,
    )


def _code(repo="u/app", path=".github/workflows/ci.yml", rule="zizmor:artipacked", line=3):
    return CodeFinding(
        repo_full_name=repo, file_path=path, line_start=line, line_end=line, rule_id=rule,
        message="m", severity="WARNING", cwe_ids=[], owasp_categories=[], code_snippet="x",
        tool="zizmor", detected_at=NOW,
    )


def _exc(db, kind="dependency", repo="u/app", key="npm|lodash|GHSA-1", **kwargs):
    row = FindingExceptionRepository(db).upsert_active(
        kind=kind, repo_full_name=repo, finding_key=key,
        status=kwargs.pop("status", "accepted"), reason=kwargs.pop("reason", "修正版が無い"),
        expires_at=kwargs.pop("expires_at", NOW + timedelta(days=30)),
        approver=kwargs.pop("approver", "u"),
    )
    return row


class TestKeys:
    def test_dependency_key_excludes_the_version(self):
        assert dependency_key("npm", "lodash", "GHSA-1") == "npm|lodash|GHSA-1"

    def test_code_key_excludes_the_line_number(self):
        assert code_key("a/b.yml", "zizmor:x") == "a/b.yml|zizmor:x"

    def test_key_of_finding_accepts_rows_and_dicts(self):
        assert key_of_finding("dependency", _dep()) == "npm|lodash|GHSA-1"
        assert key_of_finding("dependency", snapshot_of(_dep())) == "npm|lodash|GHSA-1"
        assert key_of_finding("code", _code()) == ".github/workflows/ci.yml|zizmor:artipacked"


class TestActiveExceptions:
    def test_a_live_exception_is_active(self, db_session):
        _exc(db_session)
        assert active_exceptions(db_session, "dependency").count() == 1

    def test_an_expired_exception_is_not_active_even_before_the_job_ends_it(self, db_session):
        _exc(db_session, expires_at=NOW - timedelta(seconds=1))
        assert active_exceptions(db_session, "dependency").count() == 0

    def test_an_ended_exception_is_not_active(self, db_session):
        repo = FindingExceptionRepository(db_session)
        repo.end(_exc(db_session))
        assert active_exceptions(db_session, "dependency").count() == 0

    def test_exception_without_expiry_stays_active(self, db_session):
        _exc(db_session, status="false_positive", expires_at=None)
        assert active_exceptions(db_session, "dependency").count() == 1

    def test_kinds_are_separate(self, db_session):
        _exc(db_session)
        assert active_exceptions(db_session, "code").count() == 0

    def test_exception_map_is_keyed_by_repo_and_key(self, db_session):
        row = _exc(db_session)
        assert exception_map(db_session, "dependency", {"u/app"}) == {
            ("u/app", "npm|lodash|GHSA-1"): row,
        }
        assert exception_map(db_session, "dependency", set()) == {}
        assert exception_map(db_session, "dependency", {"other/repo"}) == {}


class TestNotExcepted:
    def test_removes_only_dependency_findings_with_an_active_exception(self, db_session):
        db_session.add_all([_dep(osv="GHSA-1"), _dep(osv="GHSA-2"), _dep(repo="v/x", osv="GHSA-1")])
        db_session.commit()
        _exc(db_session)

        rows = not_excepted(db_session.query(DependencyFinding), "dependency").all()

        assert sorted((r.repo_full_name, r.osv_id) for r in rows) == [
            ("u/app", "GHSA-2"), ("v/x", "GHSA-1"),
        ]

    def test_code_findings_match_on_file_and_rule_regardless_of_the_line(self, db_session):
        db_session.add_all([_code(line=3), _code(line=30), _code(rule="zizmor:other")])
        db_session.commit()
        _exc(db_session, kind="code", key=".github/workflows/ci.yml|zizmor:artipacked")

        rows = not_excepted(db_session.query(CodeFinding), "code").all()

        assert [r.rule_id for r in rows] == ["zizmor:other"]

    def test_expired_exception_does_not_hide_the_finding(self, db_session):
        db_session.add(_dep())
        db_session.commit()
        _exc(db_session, expires_at=NOW - timedelta(days=1))

        assert not_excepted(db_session.query(DependencyFinding), "dependency").count() == 1


class TestDropExcepted:
    def test_drops_snapshots_that_have_an_active_exception(self, db_session):
        _exc(db_session)
        snaps = [snapshot_of(_dep(osv="GHSA-1")), snapshot_of(_dep(osv="GHSA-2"))]

        kept = drop_excepted(db_session, "dependency", snaps)

        assert [s["osv_id"] for s in kept] == ["GHSA-2"]

    def test_returns_everything_when_there_is_no_exception(self, db_session):
        snaps = [snapshot_of(_dep())]
        assert drop_excepted(db_session, "dependency", snaps) == snaps
        assert drop_excepted(db_session, "dependency", []) == []


class TestFindingExistsAndFindingsFor:
    def test_dependency_finding_exists_including_resolved(self, db_session):
        db_session.add(_dep(resolved=True))
        db_session.commit()
        assert finding_exists(db_session, "dependency", "u/app", "npm|lodash|GHSA-1") is True
        assert finding_exists(db_session, "dependency", "u/app", "npm|lodash|GHSA-9") is False
        assert finding_exists(db_session, "dependency", "u/app", "broken") is False

    def test_code_finding_exists_when_the_path_contains_a_separator(self, db_session):
        db_session.add(_code(path="a|b/ci.yml"))
        db_session.commit()
        assert finding_exists(db_session, "code", "u/app", "a|b/ci.yml|zizmor:artipacked") is True
        assert finding_exists(db_session, "code", "u/app", "no-separator") is False
        assert finding_exists(db_session, "unknown", "u/app", "x") is False

    def test_findings_for_returns_only_unresolved_findings(self, db_session):
        db_session.add_all([_dep(osv="GHSA-1"), _dep(osv="GHSA-1", repo="v/x"),
                            _dep(osv="GHSA-2", resolved=True)])
        db_session.add_all([_code(line=1), _code(line=2), _code(rule="zizmor:other")])
        db_session.commit()

        dep = findings_for(db_session, FindingException(
            kind="dependency", repo_full_name="u/app", finding_key="npm|lodash|GHSA-1"))
        resolved = findings_for(db_session, FindingException(
            kind="dependency", repo_full_name="u/app", finding_key="npm|lodash|GHSA-2"))
        code = findings_for(db_session, FindingException(
            kind="code", repo_full_name="u/app",
            finding_key=".github/workflows/ci.yml|zizmor:artipacked"))
        broken = findings_for(db_session, FindingException(
            kind="code", repo_full_name="u/app", finding_key="nosep"))

        assert len(dep) == 1 and resolved == [] and len(code) == 2 and broken == []

    def test_findings_for_a_malformed_dependency_key_is_empty(self, db_session):
        assert findings_for(db_session, FindingException(
            kind="dependency", repo_full_name="u/app", finding_key="x|y")) == []


class TestRepository:
    def test_upsert_updates_the_active_exception_instead_of_adding_another(self, db_session):
        first = _exc(db_session, reason="最初")
        again = _exc(db_session, reason="更新", approver="v")

        assert again.id == first.id
        assert (again.reason, again.approver) == ("更新", "v")
        assert db_session.query(FindingException).count() == 1

    def test_changing_the_expiry_resets_the_notice_flag(self, db_session):
        row = _exc(db_session)
        row.expiry_notified_at = NOW
        db_session.commit()

        assert _exc(db_session).expiry_notified_at is None

    def test_a_new_exception_is_created_after_the_previous_one_ended(self, db_session):
        repo = FindingExceptionRepository(db_session)
        first = repo.end(_exc(db_session))
        second = _exc(db_session)

        assert second.id != first.id
        assert first.ended_reason == "revoked"

    def test_find_filters_and_hides_ended_by_default(self, db_session):
        repo = FindingExceptionRepository(db_session)
        live = _exc(db_session, key="npm|a|1")
        ended = repo.end(_exc(db_session, key="npm|b|2"))
        _exc(db_session, kind="code", repo="v/x", key="f|r")

        assert [r.id for r in repo.find(kind="dependency")] == [live.id]
        assert {r.id for r in repo.find(kind="dependency", include_ended=True)} == {
            live.id, ended.id,
        }
        assert len(repo.find(repo="v/x")) == 1
        assert len(repo.find(owner="v")) == 1
        assert repo.get(live.id) is not None and repo.get(9999) is None

    def test_expire_due_ends_only_expired_exceptions(self, db_session):
        repo = FindingExceptionRepository(db_session)
        # 期限切れの例外は、upsert の時点では未来にして作り、あとから過去にする
        old = _exc(db_session, key="npm|a|1")
        old.expires_at = NOW - timedelta(hours=1)
        _exc(db_session, key="npm|b|2")
        _exc(db_session, key="npm|c|3", status="false_positive", expires_at=None)
        db_session.commit()

        due = repo.expire_due(NOW)

        assert [r.id for r in due] == [old.id]
        assert due[0].ended_reason == "expired"

    def test_due_soon_returns_each_accepted_exception_once(self, db_session):
        repo = FindingExceptionRepository(db_session)
        soon = _exc(db_session, key="npm|a|1", expires_at=NOW + timedelta(days=3))
        _exc(db_session, key="npm|b|2", expires_at=NOW + timedelta(days=20))
        _exc(db_session, key="npm|c|3", status="not_affected",
             expires_at=NOW + timedelta(days=2))

        first = repo.due_soon(NOW, 7)
        second = repo.due_soon(NOW, 7)

        assert [r.id for r in first] == [soon.id]
        assert second == []

    def test_active_accepted_excludes_other_statuses(self, db_session):
        repo = FindingExceptionRepository(db_session)
        accepted = _exc(db_session, key="npm|a|1")
        _exc(db_session, key="npm|b|2", status="false_positive", expires_at=None)

        assert [r.id for r in repo.active_accepted("dependency")] == [accepted.id]
