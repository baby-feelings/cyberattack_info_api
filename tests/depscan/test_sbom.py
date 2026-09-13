"""app.depscan.sbom（CycloneDX/SPDX SBOMエクスポート、Issue #133）のテスト。"""
from datetime import datetime, timezone

from app.depscan.models import DependencyFinding
from app.depscan.sbom import build_cyclonedx_sbom, build_purl, build_spdx_sbom

_NOW = datetime.now(timezone.utc)


def _finding(**kwargs) -> DependencyFinding:
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
        "cve_ids": ["CVE-2024-0001"],
        "manifest_path": "requirements.txt",
        "detected_at": _NOW,
    }
    defaults.update(kwargs)
    return DependencyFinding(**defaults)


class TestBuildPurl:
    def test_pypi(self):
        assert build_purl("PyPI", "cryptography", "3.4.7") == "pkg:pypi/cryptography@3.4.7"

    def test_pypi_normalizes_underscores_and_case(self):
        """PEP 503正規化: 大文字小文字・区切り文字（_ . -）の違いを無視する。"""
        assert build_purl("PyPI", "Django_Rest.Framework", "1.0") == (
            "pkg:pypi/django-rest-framework@1.0"
        )

    def test_npm_unscoped(self):
        assert build_purl("npm", "axios", "1.6.0") == "pkg:npm/axios@1.6.0"

    def test_npm_scoped(self):
        assert build_purl("npm", "@babel/core", "7.24.0") == "pkg:npm/babel/core@7.24.0"

    def test_go(self):
        assert build_purl("Go", "github.com/gorilla/mux", "1.8.0") == (
            "pkg:golang/github.com%2Fgorilla%2Fmux@1.8.0"
        )

    def test_maven_splits_group_and_artifact(self):
        assert build_purl("Maven", "org.apache:commons-lang3", "3.12.0") == (
            "pkg:maven/org.apache/commons-lang3@3.12.0"
        )

    def test_rubygems(self):
        assert build_purl("RubyGems", "rails", "7.1.0") == "pkg:gem/rails@7.1.0"

    def test_nuget(self):
        assert build_purl("NuGet", "Newtonsoft.Json", "13.0.3") == (
            "pkg:nuget/Newtonsoft.Json@13.0.3"
        )

    def test_crates_io(self):
        assert build_purl("crates.io", "serde", "1.0.0") == "pkg:cargo/serde@1.0.0"

    def test_packagist_splits_vendor_and_name(self):
        assert build_purl("Packagist", "symfony/console", "6.4.0") == (
            "pkg:composer/symfony/console@6.4.0"
        )

    def test_hex(self):
        assert build_purl("Hex", "phoenix", "1.7.0") == "pkg:hex/phoenix@1.7.0"

    def test_pub(self):
        assert build_purl("Pub", "http", "1.2.0") == "pkg:pub/http@1.2.0"

    def test_unknown_ecosystem_falls_back_to_lowercase_type(self):
        assert build_purl("Something", "foo", "1.0") == "pkg:something/foo@1.0"


class TestBuildCycloneDxSbom:
    def test_basic_structure(self):
        sbom = build_cyclonedx_sbom("baby-feelings/baby_grow", [_finding()])
        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["specVersion"] == "1.5"
        assert sbom["metadata"]["component"]["name"] == "baby-feelings/baby_grow"
        assert len(sbom["components"]) == 1
        assert sbom["components"][0]["purl"] == "pkg:pypi/cryptography@3.4.7"
        assert len(sbom["vulnerabilities"]) == 1
        vuln = sbom["vulnerabilities"][0]
        assert vuln["id"] == "GHSA-test-0001"
        assert vuln["affects"] == [{"ref": "pkg:pypi/cryptography@3.4.7"}]
        assert vuln["ratings"][0]["severity"] == "high"
        assert vuln["ratings"][0]["score"] == 7.5
        assert vuln["references"] == [{"id": "CVE-2024-0001", "source": {"name": "NVD"}}]
        assert "3.4.8" in vuln["recommendation"]

    def test_deduplicates_components_across_multiple_cves(self):
        """同一パッケージに複数CVEが紐づく場合、componentは1つにまとまること。"""
        findings = [
            _finding(osv_id="GHSA-a", cve_ids=["CVE-2024-0001"]),
            _finding(osv_id="GHSA-b", cve_ids=["CVE-2024-0002"]),
        ]
        sbom = build_cyclonedx_sbom("u/r", findings)
        assert len(sbom["components"]) == 1
        assert len(sbom["vulnerabilities"]) == 2

    def test_no_references_when_no_cve_ids(self):
        sbom = build_cyclonedx_sbom("u/r", [_finding(cve_ids=[])])
        assert "references" not in sbom["vulnerabilities"][0]

    def test_no_ratings_when_no_severity_or_score(self):
        sbom = build_cyclonedx_sbom("u/r", [_finding(severity=None, cvss_score=None)])
        assert "ratings" not in sbom["vulnerabilities"][0]

    def test_no_recommendation_when_no_fixed_versions(self):
        sbom = build_cyclonedx_sbom("u/r", [_finding(fixed_versions=[])])
        assert "recommendation" not in sbom["vulnerabilities"][0]

    def test_empty_findings_produces_empty_sbom(self):
        sbom = build_cyclonedx_sbom("u/r", [])
        assert sbom["components"] == []
        assert sbom["vulnerabilities"] == []


class TestBuildSpdxSbom:
    def test_basic_structure(self):
        sbom = build_spdx_sbom("baby-feelings/baby_grow", [_finding()])
        assert sbom["spdxVersion"] == "SPDX-2.3"
        assert sbom["name"] == "baby-feelings/baby_grow"
        assert len(sbom["packages"]) == 1
        pkg = sbom["packages"][0]
        assert pkg["name"] == "cryptography"
        assert pkg["versionInfo"] == "3.4.7"
        assert pkg["externalRefs"][0]["referenceLocator"] == "pkg:pypi/cryptography@3.4.7"

    def test_deduplicates_packages_across_multiple_cves(self):
        findings = [
            _finding(osv_id="GHSA-a"),
            _finding(osv_id="GHSA-b"),
        ]
        sbom = build_spdx_sbom("u/r", findings)
        assert len(sbom["packages"]) == 1

    def test_no_vulnerability_data_in_spdx(self):
        """SPDX 2.3のコア仕様には脆弱性を表現する概念が無いため、
        vulnerabilities相当のキーを含まないこと。"""
        sbom = build_spdx_sbom("u/r", [_finding()])
        assert "vulnerabilities" not in sbom

    def test_empty_findings_produces_empty_package_list(self):
        sbom = build_spdx_sbom("u/r", [])
        assert sbom["packages"] == []
