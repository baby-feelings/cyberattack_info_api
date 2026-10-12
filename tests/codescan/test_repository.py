"""app.codescan.repository（CodeFinding の永続化）のテスト。"""
import os
from datetime import UTC, datetime, timedelta

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")

from app.codescan.models import CodeFinding  # noqa: E402
from app.codescan.repository import CodeFindingRepository, key_of  # noqa: E402
from tests.codescan.support import make_finding  # noqa: E402

_NOW = datetime.now(UTC)

_RULE_ID = "python.lang.security.audit.hardcoded-password"


class TestUpsertRepoFindings:
    def test_inserts_new_finding(self, db_session):
        rec = {
            "repo_full_name": "owner/repo", "file_path": "a.py", "line_start": 1,
            "line_end": 1, "rule_id": "rule.x", "message": "m", "severity": "ERROR",
            "cwe_ids": [], "owasp_categories": [], "code_snippet": "x",
            "cvss_score": 5.0, "cvss_vector": "v", "detected_at": _NOW,
            "resolved_at": None,
        }
        inserted, snapshots = CodeFindingRepository(db_session).upsert("owner/repo", [rec])
        assert inserted == 1
        assert len(snapshots) == 1
        assert db_session.query(CodeFinding).count() == 1

    def test_duplicate_keys_in_same_batch_counted_once(self, db_session):
        rec = {
            "repo_full_name": "owner/repo", "file_path": "a.py", "line_start": 1,
            "line_end": 1, "rule_id": "rule.x", "message": "m", "severity": "ERROR",
            "cwe_ids": [], "owasp_categories": [], "code_snippet": "x",
            "cvss_score": 5.0, "cvss_vector": "v", "detected_at": _NOW,
            "resolved_at": None,
        }
        inserted, _ = CodeFindingRepository(db_session).upsert("owner/repo", [rec, dict(rec)])
        assert inserted == 1

    def test_existing_unresolved_finding_is_updated_not_duplicated(self, db_session):
        make_finding(db_session, message="old message", severity="WARNING")
        rec = {
            "repo_full_name": "baby-feelings/baby_grow", "file_path": "app/main.py",
            "line_start": 10, "line_end": 10, "rule_id": _RULE_ID,
            "message": "new message", "severity": "ERROR", "cwe_ids": ["CWE-798"],
            "owasp_categories": [], "code_snippet": "x", "cvss_score": 9.0,
            "cvss_vector": "v2", "detected_at": _NOW, "resolved_at": None,
        }
        repository = CodeFindingRepository(db_session)
        inserted, snapshots = repository.upsert("baby-feelings/baby_grow", [rec])
        assert inserted == 0
        assert snapshots == []
        assert db_session.query(CodeFinding).count() == 1
        updated = db_session.query(CodeFinding).first()
        assert updated.message == "new message"
        assert updated.severity == "ERROR"

    def test_reoccurrence_of_resolved_finding_reopens_it(self, db_session):
        make_finding(db_session, resolved_at=_NOW)
        rec = {
            "repo_full_name": "baby-feelings/baby_grow", "file_path": "app/main.py",
            "line_start": 10, "line_end": 10, "rule_id": _RULE_ID,
            "message": "m", "severity": "ERROR", "cwe_ids": [], "owasp_categories": [],
            "code_snippet": "x", "cvss_score": 5.0, "cvss_vector": "v",
            "detected_at": _NOW, "resolved_at": None,
        }
        repository = CodeFindingRepository(db_session)
        inserted, snapshots = repository.upsert("baby-feelings/baby_grow", [rec])
        assert inserted == 0  # 再発は新規カウントしない
        updated = db_session.query(CodeFinding).first()
        assert updated.resolved_at is None


class TestResolveStaleRepoFindings:
    def test_marks_unmatched_findings_as_resolved(self, db_session):
        make_finding(db_session)
        resolved = CodeFindingRepository(db_session).resolve_stale("baby-feelings/baby_grow", set())
        assert resolved == 1
        updated = db_session.query(CodeFinding).first()
        assert updated.resolved_at is not None

    def test_keeps_matching_findings_unresolved(self, db_session):
        make_finding(db_session)
        key = ("baby-feelings/baby_grow", "app/main.py", _RULE_ID, 10)
        resolved = CodeFindingRepository(db_session).resolve_stale("baby-feelings/baby_grow", {key})
        assert resolved == 0
        updated = db_session.query(CodeFinding).first()
        assert updated.resolved_at is None

    def test_only_affects_specified_repo(self, db_session):
        make_finding(db_session, repo_full_name="other/repo")
        resolved = CodeFindingRepository(db_session).resolve_stale("baby-feelings/baby_grow", set())
        assert resolved == 0


class TestDeleteOldCodescanRecords:
    def test_deletes_old_resolved_records(self, db_session):
        old_date = _NOW - timedelta(days=200)
        make_finding(db_session, resolved_at=old_date)
        deleted = CodeFindingRepository(db_session).delete_old_resolved()
        assert deleted == 1
        assert db_session.query(CodeFinding).count() == 0

    def test_does_not_delete_unresolved_records(self, db_session):
        make_finding(db_session, resolved_at=None)
        deleted = CodeFindingRepository(db_session).delete_old_resolved()
        assert deleted == 0
        assert db_session.query(CodeFinding).count() == 1

    def test_does_not_delete_recently_resolved_records(self, db_session):
        make_finding(db_session, resolved_at=_NOW - timedelta(days=1))
        deleted = CodeFindingRepository(db_session).delete_old_resolved()
        assert deleted == 0


class TestSync:
    def _record(self, **kw):
        base = {
            "repo_full_name": "o/r", "file_path": "a.py", "line_start": 1, "line_end": 1,
            "rule_id": _RULE_ID, "message": "m", "severity": "ERROR", "cwe_ids": ["CWE-798"],
            "owasp_categories": [], "code_snippet": "x", "cvss_score": 7.4,
            "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "detected_at": datetime.now(UTC), "tool": "semgrep",
        }
        base.update(kw)
        return base

    def test_inserts_new_and_resolves_stale_in_one_call(self, db_session):
        make_finding(db_session, repo_full_name="o/r", file_path="old.py", rule_id="old.rule")
        result = CodeFindingRepository(db_session).sync("o/r", [self._record()])

        assert result.inserted == 1
        assert [s["file_path"] for s in result.new_snapshots] == ["a.py"]
        assert result.resolved == 1  # old.py は今回検知されなかったので解決済みになる
        assert db_session.query(CodeFinding).filter(CodeFinding.resolved_at.is_(None)).count() == 1

    def test_second_sync_of_same_records_inserts_nothing(self, db_session):
        repo = CodeFindingRepository(db_session)
        repo.sync("o/r", [self._record()])
        result = repo.sync("o/r", [self._record()])
        assert (result.inserted, result.resolved, result.new_snapshots) == (0, 0, [])


def test_key_of_uses_repo_file_rule_and_line():
    rec = {"repo_full_name": "o/r", "file_path": "a.py", "rule_id": "r", "line_start": 3}
    assert key_of(rec) == ("o/r", "a.py", "r", 3)
