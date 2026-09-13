"""app.depscan.priority（DEPSCANの説明可能な優先度推薦、Issue #135）のテスト。

app.depscan.router から切り出したモジュール。元は tests/depscan/test_depscan.py の
TestFetchKevMap・TestComputePriorityReasonsとしてテストされていたものを、
モジュール分割に合わせて移動した（アサーション内容は変更していない）。
GET /api/depscan 経由の統合テスト（priority_reasons フィールド）は
引き続き tests/depscan/test_depscan.py の TestListDepscanPriorityReasons に残す。
"""
import os
from datetime import datetime, timezone

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.depscan.models import DependencyFinding  # noqa: E402
from app.depscan.priority import _compute_priority_reasons, _fetch_kev_map  # noqa: E402
from app.depscan.schemas import RepoAssetContextOut  # noqa: E402
from app.kev.models import Vulnerability  # noqa: E402

_NOW = datetime.now(timezone.utc)


def _make_finding(db_session, **kwargs) -> DependencyFinding:
    defaults = {
        "repo_full_name": "baby-feelings/baby_grow",
        "ecosystem": "PyPI",
        "package_name": "cryptography",
        "installed_version": "3.4.7",
        "osv_id": "GHSA-test-0001",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "summary": "Test vulnerability",
        "fixed_versions": ["3.4.8"],
        "manifest_path": "requirements.txt",
        "detected_at": _NOW,
        "resolved_at": None,
    }
    defaults.update(kwargs)
    record = DependencyFinding(**defaults)
    db_session.add(record)
    db_session.commit()
    return record


class TestFetchKevMap:
    def test_returns_map_for_matching_cve_ids(self, db_session):
        db_session.add(Vulnerability(
            cve_id="CVE-2024-0001", vendor_project="V", product="P",
            vulnerability_name="n", description="d", required_action=None,
            date_added=_NOW.date(),
        ))
        db_session.commit()
        finding = _make_finding(db_session, cve_ids=["CVE-2024-0001"])

        result = _fetch_kev_map(db_session, [finding])

        assert set(result.keys()) == {"CVE-2024-0001"}

    def test_excludes_non_kev_cve_ids(self, db_session):
        finding = _make_finding(db_session, cve_ids=["CVE-2024-9999"])
        result = _fetch_kev_map(db_session, [finding])
        assert result == {}

    def test_empty_when_no_cve_ids(self, db_session):
        finding = _make_finding(db_session, cve_ids=[])
        result = _fetch_kev_map(db_session, [finding])
        assert result == {}


class TestComputePriorityReasons:
    def _finding(self, **kwargs) -> DependencyFinding:
        defaults = {
            "repo_full_name": "u/r", "ecosystem": "PyPI", "package_name": "pkg",
            "installed_version": "1.0.0", "osv_id": "GHSA-x", "summary": "s",
            "fixed_versions": [], "cve_ids": [], "manifest_path": "requirements.txt",
            "detected_at": _NOW,
        }
        defaults.update(kwargs)
        return DependencyFinding(**defaults)

    def _vuln(self, cve_id: str, epss_score: float | None) -> Vulnerability:
        return Vulnerability(
            cve_id=cve_id, vendor_project="V", product="P", vulnerability_name="n",
            description="d", required_action=None, date_added=_NOW.date(),
            epss_score=epss_score,
        )

    def test_no_reasons_when_nothing_matches(self):
        finding = self._finding()
        assert _compute_priority_reasons(finding, None, {}) == []

    def test_kev_listed_when_cve_in_kev_map(self):
        finding = self._finding(cve_ids=["CVE-2024-0001"])
        kev_map = {"CVE-2024-0001": self._vuln("CVE-2024-0001", epss_score=None)}
        assert _compute_priority_reasons(finding, None, kev_map) == ["kev_listed"]

    def test_epss_high_added_when_score_above_threshold(self):
        finding = self._finding(cve_ids=["CVE-2024-0001"])
        kev_map = {"CVE-2024-0001": self._vuln("CVE-2024-0001", epss_score=0.9)}
        reasons = _compute_priority_reasons(finding, None, kev_map)
        assert reasons == ["kev_listed", "epss_high"]

    def test_epss_high_not_added_when_score_below_threshold(self):
        finding = self._finding(cve_ids=["CVE-2024-0001"])
        kev_map = {"CVE-2024-0001": self._vuln("CVE-2024-0001", epss_score=0.1)}
        reasons = _compute_priority_reasons(finding, None, kev_map)
        assert reasons == ["kev_listed"]

    def test_reachable_reason(self):
        finding = self._finding(reachability="reachable")
        assert _compute_priority_reasons(finding, None, {}) == ["reachable"]

    def test_unreachable_does_not_add_reason(self):
        finding = self._finding(reachability="unreachable")
        assert _compute_priority_reasons(finding, None, {}) == []

    def test_public_repo_reason(self):
        finding = self._finding(repo_visibility="public")
        assert _compute_priority_reasons(finding, None, {}) == ["public_repo"]

    def test_private_repo_does_not_add_reason(self):
        finding = self._finding(repo_visibility="private")
        assert _compute_priority_reasons(finding, None, {}) == []

    def test_asset_context_reasons(self):
        finding = self._finding()
        ctx = RepoAssetContextOut(
            repo_full_name="u/r", is_production=True, is_internet_facing=True,
            importance="high", updated_at=_NOW.isoformat(),
        )
        reasons = _compute_priority_reasons(finding, ctx, {})
        assert set(reasons) == {
            "internet_facing_asset", "production_asset", "high_importance_asset",
        }

    def test_asset_context_with_low_importance_and_flags_false(self):
        finding = self._finding()
        ctx = RepoAssetContextOut(
            repo_full_name="u/r", is_production=False, is_internet_facing=False,
            importance="low", updated_at=_NOW.isoformat(),
        )
        assert _compute_priority_reasons(finding, ctx, {}) == []

    def test_combines_all_signals(self):
        finding = self._finding(
            cve_ids=["CVE-2024-0001"], reachability="reachable", repo_visibility="public",
        )
        kev_map = {"CVE-2024-0001": self._vuln("CVE-2024-0001", epss_score=0.9)}
        ctx = RepoAssetContextOut(
            repo_full_name="u/r", is_production=True, is_internet_facing=True,
            importance="high", updated_at=_NOW.isoformat(),
        )
        reasons = _compute_priority_reasons(finding, ctx, kev_map)
        assert set(reasons) == {
            "kev_listed", "epss_high", "reachable", "public_repo",
            "internet_facing_asset", "production_asset", "high_importance_asset",
        }
