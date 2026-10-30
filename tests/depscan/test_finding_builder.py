"""app.depscan.finding_builder（OSV 照合と検知レコードの構築）のテスト。"""
import os
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

import httpx  # noqa: E402

TEST_API_KEY = "test-api-key-for-pytest"
HEADERS = {"X-API-KEY": TEST_API_KEY}
_NOW = datetime.now(UTC)
_REPO = "app.core.github.repo.GitHubRepo"

from app.depscan.finding_builder import FindingBuilder, build_findings  # noqa: E402


class TestBuildFindings:
    def test_builds_records_from_hits(self):
        dep_to_repos = {("PyPI", "cryptography", "3.4.7"): [("u/repo1", "requirements.txt")]}
        vuln = {
            "id": "GHSA-crypto-001",
            "summary": "Vulnerable crypto",
            "affected": [
                {"ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.4.8"}]}]}
            ],
            "database_specific": {"severity": "HIGH"},
        }
        with patch(
            "app.depscan.finding_builder.query_versions_batch",
            return_value={("PyPI", "cryptography", "3.4.7"): ["GHSA-crypto-001"]},
        ), patch("app.depscan.finding_builder.fetch_vuln_by_id", return_value=vuln):
            records = build_findings(dep_to_repos)

        assert len(records) == 1
        rec = records[0]
        assert rec["repo_full_name"] == "u/repo1"
        assert rec["osv_id"] == "GHSA-crypto-001"
        assert rec["severity"] == "HIGH"
        assert rec["fixed_versions"] == ["3.4.8"]

    def test_no_hits_returns_empty(self):
        with patch("app.depscan.finding_builder.query_versions_batch", return_value={}):
            assert build_findings({("PyPI", "pkg", "1.0.0"): [("u/r", "requirements.txt")]}) == []

    def test_vuln_fetch_failure_skipped(self):
        dep_to_repos = {("PyPI", "pkg", "1.0.0"): [("u/r", "requirements.txt")]}
        with patch(
            "app.depscan.finding_builder.query_versions_batch",
            return_value={("PyPI", "pkg", "1.0.0"): ["GHSA-x"]},
        ), patch(
            "app.depscan.finding_builder.fetch_vuln_by_id",
            side_effect=httpx.HTTPStatusError("500", request=MagicMock(), response=MagicMock()),
        ):
            assert build_findings(dep_to_repos) == []

    def test_default_reachability_is_unknown(self):
        """_apply_reachabilityで上書きされる前のフォールバック既定値。"""
        dep_to_repos = {("PyPI", "cryptography", "3.4.7"): [("u/repo1", "requirements.txt")]}
        vuln = {"id": "GHSA-x", "summary": "vuln", "affected": []}
        with patch(
            "app.depscan.finding_builder.query_versions_batch",
            return_value={("PyPI", "cryptography", "3.4.7"): ["GHSA-x"]},
        ), patch("app.depscan.finding_builder.fetch_vuln_by_id", return_value=vuln):
            records = build_findings(dep_to_repos)
        assert records[0]["reachability"] == "unknown"

    def test_sets_repo_visibility_from_map(self):
        """Issue #131: repo_visibilityマップの値がレコードに反映されること。"""
        dep_to_repos = {("PyPI", "cryptography", "3.4.7"): [("u/repo1", "requirements.txt")]}
        vuln = {"id": "GHSA-x", "summary": "vuln", "affected": []}
        with patch(
            "app.depscan.finding_builder.query_versions_batch",
            return_value={("PyPI", "cryptography", "3.4.7"): ["GHSA-x"]},
        ), patch("app.depscan.finding_builder.fetch_vuln_by_id", return_value=vuln):
            records = build_findings(dep_to_repos, {"u/repo1": "private"})
        assert records[0]["repo_visibility"] == "private"

    def test_repo_visibility_none_when_map_missing_entry(self):
        """repo_visibilityマップが渡されない/該当リポジトリが無い場合はNoneのまま。"""
        dep_to_repos = {("PyPI", "cryptography", "3.4.7"): [("u/repo1", "requirements.txt")]}
        vuln = {"id": "GHSA-x", "summary": "vuln", "affected": []}
        with patch(
            "app.depscan.finding_builder.query_versions_batch",
            return_value={("PyPI", "cryptography", "3.4.7"): ["GHSA-x"]},
        ), patch("app.depscan.finding_builder.fetch_vuln_by_id", return_value=vuln):
            records = build_findings(dep_to_repos)
        assert records[0]["repo_visibility"] is None


class TestBuildFindingsInfersFixedVersion:
    """OSVに`fixed`が無く`last_affected`だけの脆弱性は、レジストリの最新版で修正版を補う。"""

    KEY = ("PyPI", "accelerate", "1.12.0")

    @staticmethod
    def _vuln(events, pkg="accelerate", ecosystem="PyPI") -> dict:
        return {
            "id": "PYSEC-2026-3804", "summary": "path traversal",
            "affected": [{
                "package": {"name": pkg, "ecosystem": ecosystem},
                "ranges": [{"type": "ECOSYSTEM", "events": events}],
            }],
        }

    def _run(self, vuln, latest, key=None, dep_to_repos=None):
        key = key or self.KEY
        dep_to_repos = dep_to_repos or {key: [("u/r", "requirements.txt")]}
        with (
            patch(
                "app.depscan.finding_builder.query_versions_batch",
                return_value={key: [vuln["id"]]},
            ),
            patch("app.depscan.finding_builder.fetch_vuln_by_id", return_value=vuln),
            patch("app.depscan.finding_builder.fetch_latest_version", return_value=latest) as fetch,
        ):
            return build_findings(dep_to_repos), fetch

    def test_latest_newer_than_last_affected_becomes_fixed_version(self):
        vuln = self._vuln([{"introduced": "0"}, {"last_affected": "1.14.0"}])
        records, _ = self._run(vuln, "1.15.0")
        assert records[0]["fixed_versions"] == ["1.15.0"]

    def test_latest_not_newer_leaves_fixed_versions_empty(self):
        """最新版がまだ影響範囲内（修正版が未公開）なら補わない。"""
        vuln = self._vuln([{"introduced": "0"}, {"last_affected": "1.14.0"}])
        records, _ = self._run(vuln, "1.14.0")
        assert records[0]["fixed_versions"] == []

    def test_registry_failure_leaves_fixed_versions_empty(self):
        vuln = self._vuln([{"introduced": "0"}, {"last_affected": "1.14.0"}])
        records, _ = self._run(vuln, None)
        assert records[0]["fixed_versions"] == []

    def test_prerelease_latest_is_not_trusted(self):
        vuln = self._vuln([{"introduced": "0"}, {"last_affected": "1.14.0"}])
        records, _ = self._run(vuln, "2.0.0rc1")
        assert records[0]["fixed_versions"] == []

    def test_explicit_fixed_event_is_never_replaced_or_looked_up(self):
        vuln = self._vuln([{"introduced": "0"}, {"fixed": "1.13.0"}])
        records, fetch = self._run(vuln, "9.9.9")
        assert records[0]["fixed_versions"] == ["1.13.0"]
        fetch.assert_not_called()

    def test_no_last_affected_does_not_query_registry(self):
        vuln = self._vuln([{"introduced": "0"}])
        records, fetch = self._run(vuln, "9.9.9")
        assert records[0]["fixed_versions"] == []
        fetch.assert_not_called()

    def test_only_last_affected_of_the_same_package_is_used(self):
        """同じ脆弱性が別パッケージ/別エコシステムの last_affected を含んでいても無視する。"""
        vuln = self._vuln([{"introduced": "0"}, {"last_affected": "99.0.0"}], pkg="other")
        records, fetch = self._run(vuln, "1.15.0")
        assert records[0]["fixed_versions"] == []
        fetch.assert_not_called()

    def test_package_name_matched_with_pypi_normalization(self):
        vuln = self._vuln([{"introduced": "0"}, {"last_affected": "1.14.0"}], pkg="My_Pkg")
        key = ("PyPI", "my-pkg", "1.0.0")
        records, _ = self._run(vuln, "1.15.0", key=key)
        assert records[0]["fixed_versions"] == ["1.15.0"]

    def test_latest_must_exceed_every_last_affected(self):
        vuln = self._vuln([{"introduced": "0"}, {"last_affected": "1.14.0"}])
        vuln["affected"][0]["ranges"].append(
            {"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0"}, {"last_affected": "2.3.0"}]},
        )
        records, _ = self._run(vuln, "1.15.0")
        assert records[0]["fixed_versions"] == []

    def test_registry_is_queried_once_per_package(self):
        """同じパッケージ×複数リポジトリ/複数脆弱性でもレジストリは1回だけ引く。"""
        vuln = self._vuln([{"introduced": "0"}, {"last_affected": "1.14.0"}])
        dep_to_repos = {self.KEY: [("u/r1", "requirements.txt"), ("u/r2", "requirements.txt")]}
        records, fetch = self._run(vuln, "1.15.0", dep_to_repos=dep_to_repos)
        assert len(records) == 2
        assert fetch.call_count == 1


class TestFindingBuilder:
    """build_findings の実体（FindingBuilder）のキャッシュ・補完・展開の単体テスト。"""

    KEY = ("PyPI", "pkg", "1.0.0")

    def _vuln(self, **extra):
        return {
            "id": "GHSA-1", "summary": " s ", "aliases": ["CVE-2026-1", "GHSA-x", "CVE-2026-0"],
            "affected": [{"ranges": [{"events": [{"fixed": "1.0.1"}]}]}], **extra,
        }

    def test_expands_one_record_per_repo_with_shared_fields_and_cve_ids(self):
        dep_to_repos = {self.KEY: [("u/a", "requirements.txt"), ("u/b", "sub/requirements.txt")]}
        with patch("app.depscan.finding_builder.query_versions_batch",
                   return_value={self.KEY: ["GHSA-1"]}), \
             patch("app.depscan.finding_builder.fetch_vuln_by_id", return_value=self._vuln()):
            records = FindingBuilder({"u/a": "public"}).build(dep_to_repos)

        assert [r["repo_full_name"] for r in records] == ["u/a", "u/b"]
        assert records[0]["repo_visibility"] == "public"
        assert records[1]["repo_visibility"] is None
        assert records[0]["cve_ids"] == ["CVE-2026-0", "CVE-2026-1"]  # CVEのみ・ソート済み
        assert records[0]["summary"] == "s"
        assert records[0]["fixed_versions"] == ["1.0.1"]
        assert records[0]["reachability"] == "unknown"
        assert records[0]["detected_at"] == records[1]["detected_at"]

    def test_caches_vuln_details_per_osv_id_including_failures(self):
        import httpx

        k2 = ("PyPI", "other", "2.0.0")
        dep_to_repos = {self.KEY: [("u/a", "r.txt")], k2: [("u/a", "r.txt")]}
        with patch("app.depscan.finding_builder.query_versions_batch",
                   return_value={self.KEY: ["GHSA-1"], k2: ["GHSA-1"]}), \
             patch("app.depscan.finding_builder.fetch_vuln_by_id",
                   side_effect=httpx.ConnectError("down")) as mock_fetch:
            records = FindingBuilder().build(dep_to_repos)

        assert records == []
        mock_fetch.assert_called_once_with("GHSA-1")  # 失敗も含め同じIDは再取得しない

    def test_infers_fixed_version_from_registry_only_when_osv_has_no_fixed(self):
        vuln = {
            "id": "GHSA-1", "summary": "s",
            "affected": [{
                "package": {"name": "pkg", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"last_affected": "1.0.0"}]}],
            }],
        }
        with patch("app.depscan.finding_builder.query_versions_batch",
                   return_value={self.KEY: ["GHSA-1"]}), \
             patch("app.depscan.finding_builder.fetch_vuln_by_id", return_value=vuln), \
             patch(
                 "app.depscan.finding_builder.fetch_latest_version", return_value="2.0.0",
             ) as mock_latest:
            records = FindingBuilder().build({self.KEY: [("u/a", "r.txt")]})

        assert records[0]["fixed_versions"] == ["2.0.0"]
        mock_latest.assert_called_once()


class TestMaliciousAdvisory:
    """OSV の MAL-*（悪意あるパッケージ）は CVSS が無くても CRITICAL にする。"""

    def _build(self, osv_id, vuln):
        dep_to_repos = {("npm", "evil-pkg", "1.0.0"): [("u/repo1", "package-lock.json")]}
        with patch(
            "app.depscan.finding_builder.query_versions_batch",
            return_value={("npm", "evil-pkg", "1.0.0"): [osv_id]},
        ), patch("app.depscan.finding_builder.fetch_vuln_by_id", return_value=vuln):
            return build_findings(dep_to_repos)

    def test_mal_advisory_without_severity_becomes_critical(self):
        vuln = {
            "id": "MAL-2026-1234",
            "summary": "Malicious code in evil-pkg (npm)",
            "affected": [{"ranges": [{"events": [{"introduced": "0"}]}]}],
        }

        records = self._build("MAL-2026-1234", vuln)

        assert len(records) == 1
        assert records[0]["severity"] == "CRITICAL"
        assert records[0]["cvss_score"] is None

    def test_ordinary_advisory_without_severity_is_not_escalated(self):
        vuln = {
            "id": "GHSA-aaaa-bbbb-cccc",
            "summary": "x",
            "affected": [{"ranges": [{"events": [{"introduced": "0"}]}]}],
        }

        records = self._build("GHSA-aaaa-bbbb-cccc", vuln)

        assert records[0]["severity"] != "CRITICAL"
