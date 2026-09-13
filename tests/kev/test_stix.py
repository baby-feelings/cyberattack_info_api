"""app.kev.stix（STIX 2.1 Vulnerability SDO変換、Issue #134）のテスト。"""
from datetime import date, datetime, timezone

from app.kev.models import Vulnerability
from app.kev.stix import build_stix_bundle, build_stix_vulnerability, stix_vulnerability_id


def _vuln(**kwargs) -> Vulnerability:
    defaults = {
        "cve_id": "CVE-2026-12345",
        "vendor_project": "Acme",
        "product": "Widget",
        "vulnerability_name": "Acme Widget RCE",
        "description": "Remote code execution vulnerability.",
        "required_action": None,
        "date_added": date(2026, 6, 1),
    }
    defaults.update(kwargs)
    return Vulnerability(**defaults)


class TestStixVulnerabilityId:
    def test_deterministic_for_same_cve(self):
        assert stix_vulnerability_id("CVE-2026-12345") == stix_vulnerability_id("CVE-2026-12345")

    def test_different_for_different_cve(self):
        assert stix_vulnerability_id("CVE-2026-12345") != stix_vulnerability_id("CVE-2026-99999")

    def test_has_vulnerability_prefix(self):
        assert stix_vulnerability_id("CVE-2026-12345").startswith("vulnerability--")


class TestBuildStixVulnerability:
    def test_basic_fields(self):
        stix_obj = build_stix_vulnerability(_vuln())
        assert stix_obj["type"] == "vulnerability"
        assert stix_obj["spec_version"] == "2.1"
        assert stix_obj["id"] == stix_vulnerability_id("CVE-2026-12345")
        assert stix_obj["name"] == "CVE-2026-12345"
        assert "Acme Widget RCE" in stix_obj["description"]
        assert "Remote code execution" in stix_obj["description"]

    def test_external_references_include_cve_and_kev(self):
        stix_obj = build_stix_vulnerability(_vuln())
        sources = {ref["source_name"] for ref in stix_obj["external_references"]}
        assert sources == {"cve", "cisa-kev"}
        cve_ref = next(r for r in stix_obj["external_references"] if r["source_name"] == "cve")
        assert cve_ref["external_id"] == "CVE-2026-12345"

    def test_includes_required_action_in_description_when_present(self):
        stix_obj = build_stix_vulnerability(_vuln(required_action="Apply patch immediately."))
        assert "Required Action: Apply patch immediately." in stix_obj["description"]

    def test_omits_required_action_when_absent(self):
        stix_obj = build_stix_vulnerability(_vuln(required_action=None))
        assert "Required Action" not in stix_obj["description"]

    def test_created_uses_date_added(self):
        stix_obj = build_stix_vulnerability(_vuln(date_added=date(2026, 3, 15)))
        assert stix_obj["created"].startswith("2026-03-15T00:00:00.000Z")

    def test_modified_uses_updated_at_when_present(self):
        updated = datetime(2026, 7, 1, 12, 30, tzinfo=timezone.utc)
        stix_obj = build_stix_vulnerability(_vuln(updated_at=updated))
        assert stix_obj["modified"] == "2026-07-01T12:30:00.000Z"

    def test_modified_falls_back_to_created_when_updated_at_absent(self):
        stix_obj = build_stix_vulnerability(_vuln(date_added=date(2026, 3, 15), updated_at=None))
        assert stix_obj["modified"] == stix_obj["created"]

    def test_includes_epss_when_present(self):
        stix_obj = build_stix_vulnerability(_vuln(epss_score=0.87, epss_percentile=0.95))
        assert stix_obj["x_epss_score"] == 0.87
        assert stix_obj["x_epss_percentile"] == 0.95

    def test_omits_epss_when_absent(self):
        stix_obj = build_stix_vulnerability(_vuln(epss_score=None))
        assert "x_epss_score" not in stix_obj
        assert "x_epss_percentile" not in stix_obj


class TestBuildStixBundle:
    def test_bundle_structure(self):
        bundle = build_stix_bundle([_vuln(cve_id="CVE-2026-0001"), _vuln(cve_id="CVE-2026-0002")])
        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")
        assert len(bundle["objects"]) == 2
        names = {obj["name"] for obj in bundle["objects"]}
        assert names == {"CVE-2026-0001", "CVE-2026-0002"}

    def test_empty_list_produces_empty_bundle(self):
        bundle = build_stix_bundle([])
        assert bundle["objects"] == []
