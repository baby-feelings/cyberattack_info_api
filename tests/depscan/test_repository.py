"""app.depscan.repository（DependencyFinding の永続化）のテスト。"""
import os
from datetime import UTC, datetime, timedelta

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")


from app.depscan.models import DependencyFinding  # noqa: E402
from tests.depscan.support import make_finding  # noqa: E402

TEST_API_KEY = "test-api-key-for-pytest"
HEADERS = {"X-API-KEY": TEST_API_KEY}
_NOW = datetime.now(UTC)
_REPO = "app.core.github.repo.GitHubRepo"

from app.depscan.repository import DependencyFindingRepository, key_of  # noqa: E402


class TestUpsertFindings:
    def _rec(self, **kwargs):
        base = {
            "repo_full_name": "baby-feelings/baby_grow",
            "ecosystem": "PyPI",
            "package_name": "cryptography",
            "installed_version": "3.4.7",
            "osv_id": "GHSA-001",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "summary": "vuln",
            "fixed_versions": ["3.4.8"],
            "manifest_path": "requirements.txt",
            "detected_at": _NOW,
        }
        base.update(kwargs)
        return base

    def test_inserts_new_finding(self, db_session):
        inserted, snapshots = DependencyFindingRepository(db_session).upsert([self._rec()])
        assert inserted == 1
        assert snapshots[0]["osv_id"] == "GHSA-001"
        assert db_session.query(DependencyFinding).count() == 1

    def test_dedupes_within_batch(self, db_session):
        inserted, _ = DependencyFindingRepository(db_session).upsert([self._rec(), self._rec()])
        assert inserted == 1

    def test_reopens_resolved_finding(self, db_session):
        make_finding(db_session, osv_id="GHSA-001", resolved_at=_NOW)
        inserted, snapshots = DependencyFindingRepository(db_session).upsert([self._rec()])
        assert inserted == 0
        assert snapshots == []
        reopened = db_session.query(DependencyFinding).filter_by(osv_id="GHSA-001").first()
        assert reopened.resolved_at is None

    def test_existing_open_finding_not_reinserted(self, db_session):
        make_finding(db_session, osv_id="GHSA-001")
        inserted, snapshots = DependencyFindingRepository(db_session).upsert([self._rec()])
        assert inserted == 0
        assert snapshots == []

    def test_existing_open_finding_refreshes_reachability_only(self, db_session):
        """既存の未解決findingは、到達可能性だけ毎回更新し他フィールドは据え置く。"""
        make_finding(
            db_session, osv_id="GHSA-001", reachability="unreachable", summary="old summary",
        )
        DependencyFindingRepository(db_session).upsert(
            [self._rec(reachability="reachable", summary="new summary")],
        )
        finding = db_session.query(DependencyFinding).filter_by(osv_id="GHSA-001").first()
        assert finding.reachability == "reachable"
        assert finding.summary == "old summary"  # 到達可能性以外は更新されない

    def test_existing_open_finding_gets_newly_inferred_fixed_versions(self, db_session):
        """以前は修正版が空だった未解決findingに、後から判明した修正版を反映する。"""
        make_finding(db_session, osv_id="GHSA-001", fixed_versions=[])
        DependencyFindingRepository(db_session).upsert([self._rec(fixed_versions=["1.15.0"])])
        finding = db_session.query(DependencyFinding).filter_by(osv_id="GHSA-001").first()
        assert finding.fixed_versions == ["1.15.0"]

    def test_existing_fixed_versions_not_wiped_when_lookup_returns_nothing(self, db_session):
        """レジストリを一時的に引けず空になった回に、既知の修正版を消さない。"""
        make_finding(db_session, osv_id="GHSA-001", fixed_versions=["1.15.0"])
        DependencyFindingRepository(db_session).upsert([self._rec(fixed_versions=[])])
        finding = db_session.query(DependencyFinding).filter_by(osv_id="GHSA-001").first()
        assert finding.fixed_versions == ["1.15.0"]


class TestResolveStaleFindings:
    def test_marks_missing_findings_resolved(self, db_session):
        make_finding(db_session, osv_id="GHSA-stale")
        repository = DependencyFindingRepository(db_session)
        resolved, affected_repos = repository.resolve_stale(current_keys=set())
        assert resolved == 1
        assert affected_repos == {"baby-feelings/baby_grow"}
        finding = db_session.query(DependencyFinding).filter_by(osv_id="GHSA-stale").first()
        assert finding.resolved_at is not None

    def test_keeps_current_findings_open(self, db_session):
        make_finding(db_session, osv_id="GHSA-current")
        key = ("baby-feelings/baby_grow", "PyPI", "cryptography", "GHSA-current")
        repository = DependencyFindingRepository(db_session)
        resolved, affected_repos = repository.resolve_stale(current_keys={key})
        assert resolved == 0
        assert affected_repos == set()

    def test_repo_owner_prefix_scopes_to_matching_repos_only(self, db_session):
        """repo_owner_prefix指定時、他オーナーの未解決findingには一切影響しない。"""
        make_finding(
            db_session, repo_full_name="baby-feelings/baby_grow", osv_id="GHSA-baby-feelings",
        )
        make_finding(db_session, repo_full_name="octocat/hello-world", osv_id="GHSA-octocat")

        resolved, affected_repos = DependencyFindingRepository(db_session).resolve_stale(
            current_keys=set(), repo_owner_prefix="octocat",
        )

        assert resolved == 1
        assert affected_repos == {"octocat/hello-world"}
        baby_feelings_finding = (
            db_session.query(DependencyFinding).filter_by(osv_id="GHSA-baby-feelings").first()
        )
        octocat_finding = (
            db_session.query(DependencyFinding).filter_by(osv_id="GHSA-octocat").first()
        )
        assert baby_feelings_finding.resolved_at is None
        assert octocat_finding.resolved_at is not None


class TestDeleteOldDepscanRecords:
    def test_deletes_old_resolved_records(self, db_session):
        """保持期間（DEPSCAN_RETENTION_DAYS）を超えて解決済みのレコードが削除されること。"""

        old_resolved = _NOW - timedelta(days=181)
        make_finding(db_session, osv_id="GHSA-old-resolved", resolved_at=old_resolved)

        deleted = DependencyFindingRepository(db_session).delete_old_resolved()

        assert deleted == 1
        assert db_session.query(DependencyFinding).count() == 0

    def test_keeps_recently_resolved_records(self, db_session):
        """保持期間内に解決したレコードは削除されないこと。"""

        recent_resolved = _NOW - timedelta(days=1)
        make_finding(db_session, osv_id="GHSA-recent-resolved", resolved_at=recent_resolved)

        deleted = DependencyFindingRepository(db_session).delete_old_resolved()

        assert deleted == 0
        assert db_session.query(DependencyFinding).count() == 1

    def test_keeps_unresolved_records_regardless_of_age(self, db_session):
        """未解決のレコードは detected_at がどれだけ古くても削除されないこと。"""

        very_old = _NOW - timedelta(days=1000)
        make_finding(
            db_session, osv_id="GHSA-unresolved-old", detected_at=very_old, resolved_at=None,
        )

        deleted = DependencyFindingRepository(db_session).delete_old_resolved()

        assert deleted == 0
        assert db_session.query(DependencyFinding).count() == 1

    def test_empty_db_returns_zero(self, db_session):

        assert DependencyFindingRepository(db_session).delete_old_resolved() == 0


class TestSync:
    @staticmethod
    def _rec(**kwargs):
        base = {
            "repo_full_name": "octocat/app", "ecosystem": "PyPI", "package_name": "pkg",
            "installed_version": "1.0", "osv_id": "GHSA-1", "severity": "HIGH", "cvss_score": 7.5,
            "summary": "s", "fixed_versions": [], "manifest_path": "requirements.txt",
            "detected_at": _NOW,
        }
        base.update(kwargs)
        return base

    def test_inserts_new_and_resolves_stale_in_one_call(self, db_session):
        make_finding(db_session, repo_full_name="octocat/app", osv_id="GHSA-stale")
        result = DependencyFindingRepository(db_session).sync([self._rec()])

        assert result.inserted == 1
        assert [s["osv_id"] for s in result.new_snapshots] == ["GHSA-1"]
        assert result.resolved == 1  # GHSA-stale は今回検知されなかったので解決済みになる
        assert result.resolved_repos == {"octocat/app"}

    def test_repo_owner_prefix_keeps_other_owners_untouched(self, db_session):
        make_finding(db_session, repo_full_name="someone-else/app", osv_id="GHSA-other")
        result = DependencyFindingRepository(db_session).sync(
            [self._rec()], repo_owner_prefix="octocat",
        )
        assert result.resolved == 0  # 他人のリポジトリの未解決レコードは解決済みにしない
        still_open = db_session.query(DependencyFinding).filter(
            DependencyFinding.repo_full_name == "someone-else/app",
            DependencyFinding.resolved_at.is_(None),
        )
        assert still_open.count() == 1

    def test_second_sync_of_same_records_changes_nothing(self, db_session):
        repository = DependencyFindingRepository(db_session)
        repository.sync([self._rec()])
        result = repository.sync([self._rec()])
        assert (result.inserted, result.resolved, result.new_snapshots) == (0, 0, [])


def test_key_of_uses_repo_ecosystem_package_and_osv_id():
    rec = {"repo_full_name": "o/r", "ecosystem": "npm", "package_name": "p", "osv_id": "X"}
    assert key_of(rec) == ("o/r", "npm", "p", "X")
