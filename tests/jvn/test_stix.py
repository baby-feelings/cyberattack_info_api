"""app.jvn.stix（STIX 2.1 Vulnerability SDO変換、Issue #134のJVN拡張）のテスト。"""
from datetime import datetime, timezone

from app.jvn.models import JvnVulnerability
from app.jvn.stix import build_stix_bundle, build_stix_vulnerability, stix_vulnerability_id


def _vuln(**kwargs) -> JvnVulnerability:
    defaults = {
        "jvndb_id": "JVNDB-2026-000001",
        "title": "テスト脆弱性",
        "overview": "テスト概要",
        "cve_ids": ["CVE-2026-12345"],
        "severity": "High",
        "cvss_score": 9.8,
        "cvss_vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
        "affected_products": [],
        "references": [],
        "jvn_url": "https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000001.html",
        "date_published": datetime(2026, 6, 1, tzinfo=timezone.utc),
        "date_last_modified": datetime(2026, 6, 2, tzinfo=timezone.utc),
    }
    defaults.update(kwargs)
    return JvnVulnerability(**defaults)


class TestStixVulnerabilityId:
    def test_deterministic_for_same_jvndb_id(self):
        assert stix_vulnerability_id("JVNDB-2026-000001") == stix_vulnerability_id(
            "JVNDB-2026-000001",
        )

    def test_different_for_different_jvndb_id(self):
        assert stix_vulnerability_id("JVNDB-2026-000001") != stix_vulnerability_id(
            "JVNDB-2026-000002",
        )

    def test_has_vulnerability_prefix(self):
        assert stix_vulnerability_id("JVNDB-2026-000001").startswith("vulnerability--")


class TestBuildStixVulnerability:
    def test_basic_fields(self):
        stix_obj = build_stix_vulnerability(_vuln())
        assert stix_obj["type"] == "vulnerability"
        assert stix_obj["spec_version"] == "2.1"
        assert stix_obj["id"] == stix_vulnerability_id("JVNDB-2026-000001")
        assert stix_obj["name"] == "JVNDB-2026-000001"
        assert "テスト脆弱性" in stix_obj["description"]
        assert "テスト概要" in stix_obj["description"]

    def test_external_references_include_jvndb_and_cve(self):
        stix_obj = build_stix_vulnerability(_vuln(cve_ids=["CVE-2026-12345", "CVE-2026-99999"]))
        sources = [ref["source_name"] for ref in stix_obj["external_references"]]
        assert sources.count("jvndb") == 1
        assert sources.count("cve") == 2
        jvndb_ref = next(r for r in stix_obj["external_references"] if r["source_name"] == "jvndb")
        assert jvndb_ref["external_id"] == "JVNDB-2026-000001"
        assert jvndb_ref["url"] == "https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000001.html"

    def test_external_references_with_no_cve_ids(self):
        stix_obj = build_stix_vulnerability(_vuln(cve_ids=[]))
        sources = {ref["source_name"] for ref in stix_obj["external_references"]}
        assert sources == {"jvndb"}

    def test_created_and_modified_use_date_published_and_last_modified(self):
        stix_obj = build_stix_vulnerability(_vuln(
            date_published=datetime(2026, 3, 15, 1, 2, 3, tzinfo=timezone.utc),
            date_last_modified=datetime(2026, 4, 1, 4, 5, 6, tzinfo=timezone.utc),
        ))
        assert stix_obj["created"] == "2026-03-15T01:02:03.000Z"
        assert stix_obj["modified"] == "2026-04-01T04:05:06.000Z"

    def test_includes_cvss_when_present(self):
        stix_obj = build_stix_vulnerability(
            _vuln(cvss_score=9.8, cvss_vector="AV:N/AC:L/Au:N/C:C/I:C/A:C"),
        )
        assert stix_obj["x_cvss_score"] == 9.8
        assert stix_obj["x_cvss_vector"] == "AV:N/AC:L/Au:N/C:C/I:C/A:C"

    def test_omits_cvss_when_absent(self):
        stix_obj = build_stix_vulnerability(_vuln(cvss_score=None, cvss_vector=None))
        assert "x_cvss_score" not in stix_obj
        assert "x_cvss_vector" not in stix_obj


class TestBuildStixBundle:
    def test_bundle_structure(self):
        bundle = build_stix_bundle([
            _vuln(jvndb_id="JVNDB-2026-000001"),
            _vuln(jvndb_id="JVNDB-2026-000002"),
        ])
        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")
        assert len(bundle["objects"]) == 2
        names = {obj["name"] for obj in bundle["objects"]}
        assert names == {"JVNDB-2026-000001", "JVNDB-2026-000002"}

    def test_empty_list_produces_empty_bundle(self):
        bundle = build_stix_bundle([])
        assert bundle["objects"] == []
