"""app.osv.stix（STIX 2.1 Vulnerability SDO変換、Issue #134のOSV拡張）のテスト。"""
from datetime import datetime, timezone

from app.osv.models import OsvVulnerability
from app.osv.stix import build_stix_bundle, build_stix_vulnerability, stix_vulnerability_id


def _vuln(**kwargs) -> OsvVulnerability:
    defaults = {
        "osv_id": "GHSA-xxxx-xxxx-xxxx",
        "ecosystem": "PyPI",
        "package_name": "fastapi",
        "aliases": ["CVE-2026-12345"],
        "summary": "Test vulnerability summary.",
        "details": None,
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected_versions": ["0.1.0"],
        "fixed_versions": ["0.2.0"],
        "references": [],
        "published": datetime(2026, 6, 1, tzinfo=timezone.utc),
        "modified": datetime(2026, 6, 2, tzinfo=timezone.utc),
    }
    defaults.update(kwargs)
    return OsvVulnerability(**defaults)


class TestStixVulnerabilityId:
    def test_deterministic_for_same_key(self):
        assert stix_vulnerability_id(
            "GHSA-xxxx", "PyPI", "fastapi",
        ) == stix_vulnerability_id("GHSA-xxxx", "PyPI", "fastapi")

    def test_different_for_different_package(self):
        assert stix_vulnerability_id(
            "GHSA-xxxx", "PyPI", "fastapi",
        ) != stix_vulnerability_id("GHSA-xxxx", "PyPI", "django")

    def test_different_for_different_ecosystem(self):
        assert stix_vulnerability_id(
            "GHSA-xxxx", "PyPI", "fastapi",
        ) != stix_vulnerability_id("GHSA-xxxx", "npm", "fastapi")

    def test_has_vulnerability_prefix(self):
        assert stix_vulnerability_id("GHSA-xxxx", "PyPI", "fastapi").startswith("vulnerability--")


class TestBuildStixVulnerability:
    def test_basic_fields(self):
        stix_obj = build_stix_vulnerability(_vuln())
        assert stix_obj["type"] == "vulnerability"
        assert stix_obj["spec_version"] == "2.1"
        assert stix_obj["id"] == stix_vulnerability_id("GHSA-xxxx-xxxx-xxxx", "PyPI", "fastapi")
        assert stix_obj["name"] == "GHSA-xxxx-xxxx-xxxx"
        assert "Test vulnerability summary." in stix_obj["description"]

    def test_description_includes_details_when_present(self):
        stix_obj = build_stix_vulnerability(_vuln(details="Detailed explanation."))
        assert "Detailed explanation." in stix_obj["description"]

    def test_description_omits_details_when_absent(self):
        stix_obj = build_stix_vulnerability(_vuln(details=None))
        assert stix_obj["description"] == "Test vulnerability summary."

    def test_external_references_include_osv_and_cve_aliases(self):
        stix_obj = build_stix_vulnerability(
            _vuln(aliases=["CVE-2026-12345", "CVE-2026-99999", "GHSA-other"]),
        )
        sources = [ref["source_name"] for ref in stix_obj["external_references"]]
        assert sources.count("osv") == 1
        assert sources.count("cve") == 2
        cve_ids = {
            ref["external_id"] for ref in stix_obj["external_references"]
            if ref["source_name"] == "cve"
        }
        assert cve_ids == {"CVE-2026-12345", "CVE-2026-99999"}

    def test_external_references_omit_non_cve_aliases(self):
        stix_obj = build_stix_vulnerability(_vuln(aliases=["GHSA-other"]))
        sources = {ref["source_name"] for ref in stix_obj["external_references"]}
        assert sources == {"osv"}

    def test_osv_reference_url(self):
        stix_obj = build_stix_vulnerability(_vuln(osv_id="GHSA-xxxx-xxxx-xxxx"))
        osv_ref = next(r for r in stix_obj["external_references"] if r["source_name"] == "osv")
        assert osv_ref["url"] == "https://osv.dev/vulnerability/GHSA-xxxx-xxxx-xxxx"

    def test_created_and_modified_use_published_and_modified(self):
        stix_obj = build_stix_vulnerability(_vuln(
            published=datetime(2026, 3, 15, 1, 2, 3, tzinfo=timezone.utc),
            modified=datetime(2026, 4, 1, 4, 5, 6, tzinfo=timezone.utc),
        ))
        assert stix_obj["created"] == "2026-03-15T01:02:03.000Z"
        assert stix_obj["modified"] == "2026-04-01T04:05:06.000Z"

    def test_includes_custom_properties(self):
        stix_obj = build_stix_vulnerability(_vuln(ecosystem="npm", package_name="express"))
        assert stix_obj["x_ecosystem"] == "npm"
        assert stix_obj["x_package_name"] == "express"

    def test_includes_cvss_score_when_present(self):
        stix_obj = build_stix_vulnerability(_vuln(cvss_score=9.8))
        assert stix_obj["x_cvss_score"] == 9.8

    def test_omits_cvss_score_when_absent(self):
        stix_obj = build_stix_vulnerability(_vuln(cvss_score=None))
        assert "x_cvss_score" not in stix_obj


class TestBuildStixBundle:
    def test_bundle_structure(self):
        bundle = build_stix_bundle([
            _vuln(osv_id="GHSA-0001", package_name="pkg-a"),
            _vuln(osv_id="GHSA-0002", package_name="pkg-b"),
        ])
        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")
        assert len(bundle["objects"]) == 2
        names = {obj["name"] for obj in bundle["objects"]}
        assert names == {"GHSA-0001", "GHSA-0002"}

    def test_empty_list_produces_empty_bundle(self):
        bundle = build_stix_bundle([])
        assert bundle["objects"] == []
