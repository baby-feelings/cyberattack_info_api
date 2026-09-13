"""app.core.taxii（TAXII 2.1配信、Issue #134のOSV/JVN拡張）のテスト。

KEV向けの既存テストケース（tests/kev/test_taxii.py から移動）はそのまま残し、
OSV/JVNコレクションのテストを追加する。
"""
from datetime import date, datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.jvn.models import JvnVulnerability
from app.jvn.stix import stix_vulnerability_id as jvn_stix_vulnerability_id
from app.kev.models import Vulnerability
from app.kev.stix import stix_vulnerability_id as kev_stix_vulnerability_id
from app.osv.models import OsvVulnerability
from app.osv.stix import stix_vulnerability_id as osv_stix_vulnerability_id
from tests.conftest import TEST_API_KEY

_API_ROOT = "cyberattack-info-api"
_KEV_COLLECTION_ID = "d4d8f0c0-3f5f-5b1e-9c1a-6f6f6a6b6a6a"
_OSV_COLLECTION_ID = "84be1117-7e69-58ed-a0dc-d2f2bb7f60ca"
_JVN_COLLECTION_ID = "1c34f413-fd30-56cc-bf87-daf79113b5a8"
_HEADERS = {"X-API-KEY": TEST_API_KEY}


def _make_kev_vuln(db: Session, cve_id: str = "CVE-2026-00001", **kwargs) -> Vulnerability:
    defaults = {
        "vendor_project": "V", "product": "P", "vulnerability_name": "n",
        "description": "d", "required_action": None, "date_added": date.today(),
    }
    defaults.update(kwargs)
    vuln = Vulnerability(cve_id=cve_id, **defaults)
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    return vuln


def _make_osv_vuln(
    db: Session, osv_id: str = "GHSA-taxii-0001", ecosystem: str = "PyPI",
    package_name: str = "fastapi", **kwargs,
) -> OsvVulnerability:
    now = datetime.now(timezone.utc)
    defaults = {
        "aliases": ["CVE-2026-12345"],
        "summary": "s",
        "details": None,
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected_versions": [],
        "fixed_versions": [],
        "references": [],
        "published": now,
        "modified": now,
    }
    defaults.update(kwargs)
    vuln = OsvVulnerability(
        osv_id=osv_id, ecosystem=ecosystem, package_name=package_name, **defaults,
    )
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    return vuln


def _make_jvn_vuln(db: Session, jvndb_id: str = "JVNDB-2026-000001", **kwargs) -> JvnVulnerability:
    now = datetime.now(timezone.utc)
    defaults = {
        "title": "t",
        "overview": "o",
        "cve_ids": ["CVE-2026-12345"],
        "severity": "High",
        "cvss_score": 9.8,
        "cvss_vector": None,
        "affected_products": [],
        "references": [],
        "jvn_url": f"https://jvndb.jvn.jp/ja/contents/2026/{jvndb_id}.html",
        "date_published": now,
        "date_last_modified": now,
    }
    defaults.update(kwargs)
    vuln = JvnVulnerability(jvndb_id=jvndb_id, **defaults)
    db.add(vuln)
    db.commit()
    db.refresh(vuln)
    return vuln


class TestDiscovery:
    def test_requires_auth(self, client: TestClient):
        res = client.get("/taxii2/")
        assert res.status_code == 403

    def test_returns_discovery_document(self, client: TestClient, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        res = client.get("/taxii2/", headers=_HEADERS)
        assert res.status_code == 200
        assert res.headers["content-type"] == "application/taxii+json;version=2.1"
        body = res.json()
        assert body["default"] == f"/taxii2/{_API_ROOT}/"
        assert body["api_roots"] == [f"/taxii2/{_API_ROOT}/"]


class TestApiRootInfo:
    def test_returns_info_for_known_root(self, client: TestClient, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        res = client.get(f"/taxii2/{_API_ROOT}/", headers=_HEADERS)
        assert res.status_code == 200
        assert "application/taxii+json;version=2.1" in res.json()["versions"]

    def test_404_for_unknown_root(self, client: TestClient, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        res = client.get("/taxii2/unknown-root/", headers=_HEADERS)
        assert res.status_code == 404


class TestListCollections:
    def test_returns_kev_osv_jvn_collections(self, client: TestClient, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        res = client.get(f"/taxii2/{_API_ROOT}/collections/", headers=_HEADERS)
        assert res.status_code == 200
        collections = res.json()["collections"]
        assert len(collections) == 3
        ids = {c["id"] for c in collections}
        assert ids == {_KEV_COLLECTION_ID, _OSV_COLLECTION_ID, _JVN_COLLECTION_ID}
        assert all(c["can_write"] is False for c in collections)

    def test_404_for_unknown_root(self, client: TestClient, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        res = client.get("/taxii2/unknown-root/collections/", headers=_HEADERS)
        assert res.status_code == 404


class TestGetCollection:
    def test_returns_kev_collection_info(self, client: TestClient, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/{_KEV_COLLECTION_ID}/", headers=_HEADERS,
        )
        assert res.status_code == 200
        assert res.json()["id"] == _KEV_COLLECTION_ID

    def test_returns_osv_collection_info(self, client: TestClient, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/{_OSV_COLLECTION_ID}/", headers=_HEADERS,
        )
        assert res.status_code == 200
        assert res.json()["id"] == _OSV_COLLECTION_ID

    def test_returns_jvn_collection_info(self, client: TestClient, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/{_JVN_COLLECTION_ID}/", headers=_HEADERS,
        )
        assert res.status_code == 200
        assert res.json()["id"] == _JVN_COLLECTION_ID

    def test_404_for_unknown_collection(self, client: TestClient, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/00000000-0000-0000-0000-000000000000/",
            headers=_HEADERS,
        )
        assert res.status_code == 404

    def test_404_for_unknown_root(self, client: TestClient, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        res = client.get(
            f"/taxii2/unknown-root/collections/{_KEV_COLLECTION_ID}/", headers=_HEADERS,
        )
        assert res.status_code == 404


class TestListObjectsKev:
    def test_returns_stix_objects(self, client: TestClient, db_session: Session, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        _make_kev_vuln(db_session, cve_id="CVE-2026-10001")
        _make_kev_vuln(db_session, cve_id="CVE-2026-10002")

        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/{_KEV_COLLECTION_ID}/objects/", headers=_HEADERS,
        )
        assert res.status_code == 200
        objects = res.json()["objects"]
        assert len(objects) == 2
        assert all(obj["type"] == "vulnerability" for obj in objects)

    def test_filters_by_added_after(self, client: TestClient, db_session: Session, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        old = _make_kev_vuln(db_session, cve_id="CVE-2026-20001")
        old.updated_at = datetime.now(timezone.utc) - timedelta(days=10)
        db_session.commit()
        _make_kev_vuln(db_session, cve_id="CVE-2026-20002")

        cutoff = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/{_KEV_COLLECTION_ID}/objects/",
            params={"added_after": cutoff},
            headers=_HEADERS,
        )
        names = {obj["name"] for obj in res.json()["objects"]}
        assert names == {"CVE-2026-20002"}

    def test_respects_limit(self, client: TestClient, db_session: Session, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        for i in range(3):
            _make_kev_vuln(db_session, cve_id=f"CVE-2026-3000{i}")

        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/{_KEV_COLLECTION_ID}/objects/?limit=2",
            headers=_HEADERS,
        )
        assert len(res.json()["objects"]) == 2

    def test_requires_auth(self, client: TestClient):
        res = client.get(f"/taxii2/{_API_ROOT}/collections/{_KEV_COLLECTION_ID}/objects/")
        assert res.status_code == 403


class TestGetObjectKev:
    def test_returns_matching_object(self, client: TestClient, db_session: Session, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        _make_kev_vuln(db_session, cve_id="CVE-2026-40001")
        object_id = kev_stix_vulnerability_id("CVE-2026-40001")

        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/{_KEV_COLLECTION_ID}/objects/{object_id}/",
            headers=_HEADERS,
        )
        assert res.status_code == 200
        objects = res.json()["objects"]
        assert len(objects) == 1
        assert objects[0]["name"] == "CVE-2026-40001"

    def test_404_for_unknown_object(self, client: TestClient, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/{_KEV_COLLECTION_ID}/objects/"
            "vulnerability--00000000-0000-0000-0000-000000000000/",
            headers=_HEADERS,
        )
        assert res.status_code == 404


class TestListObjectsOsv:
    def test_returns_stix_objects(self, client: TestClient, db_session: Session, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        _make_osv_vuln(db_session, osv_id="GHSA-0001", package_name="pkg-a")
        _make_osv_vuln(db_session, osv_id="GHSA-0002", package_name="pkg-b")

        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/{_OSV_COLLECTION_ID}/objects/", headers=_HEADERS,
        )
        assert res.status_code == 200
        objects = res.json()["objects"]
        assert len(objects) == 2
        assert all(obj["type"] == "vulnerability" for obj in objects)

    def test_filters_by_added_after(self, client: TestClient, db_session: Session, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        old = _make_osv_vuln(db_session, osv_id="GHSA-old", package_name="pkg-old")
        old.updated_at = datetime.now(timezone.utc) - timedelta(days=10)
        db_session.commit()
        _make_osv_vuln(db_session, osv_id="GHSA-new", package_name="pkg-new")

        cutoff = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/{_OSV_COLLECTION_ID}/objects/",
            params={"added_after": cutoff},
            headers=_HEADERS,
        )
        names = {obj["name"] for obj in res.json()["objects"]}
        assert names == {"GHSA-new"}

    def test_requires_auth(self, client: TestClient):
        res = client.get(f"/taxii2/{_API_ROOT}/collections/{_OSV_COLLECTION_ID}/objects/")
        assert res.status_code == 403


class TestGetObjectOsv:
    def test_returns_matching_object(self, client: TestClient, db_session: Session, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        _make_osv_vuln(db_session, osv_id="GHSA-50001", ecosystem="PyPI", package_name="fastapi")
        object_id = osv_stix_vulnerability_id("GHSA-50001", "PyPI", "fastapi")

        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/{_OSV_COLLECTION_ID}/objects/{object_id}/",
            headers=_HEADERS,
        )
        assert res.status_code == 200
        objects = res.json()["objects"]
        assert len(objects) == 1
        assert objects[0]["name"] == "GHSA-50001"

    def test_404_for_unknown_object(self, client: TestClient, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/{_OSV_COLLECTION_ID}/objects/"
            "vulnerability--00000000-0000-0000-0000-000000000000/",
            headers=_HEADERS,
        )
        assert res.status_code == 404


class TestListObjectsJvn:
    def test_returns_stix_objects(self, client: TestClient, db_session: Session, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        _make_jvn_vuln(db_session, jvndb_id="JVNDB-2026-100001")
        _make_jvn_vuln(db_session, jvndb_id="JVNDB-2026-100002")

        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/{_JVN_COLLECTION_ID}/objects/", headers=_HEADERS,
        )
        assert res.status_code == 200
        objects = res.json()["objects"]
        assert len(objects) == 2
        assert all(obj["type"] == "vulnerability" for obj in objects)

    def test_filters_by_added_after(self, client: TestClient, db_session: Session, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        old = _make_jvn_vuln(db_session, jvndb_id="JVNDB-2026-200001")
        old.updated_at = datetime.now(timezone.utc) - timedelta(days=10)
        db_session.commit()
        _make_jvn_vuln(db_session, jvndb_id="JVNDB-2026-200002")

        cutoff = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/{_JVN_COLLECTION_ID}/objects/",
            params={"added_after": cutoff},
            headers=_HEADERS,
        )
        names = {obj["name"] for obj in res.json()["objects"]}
        assert names == {"JVNDB-2026-200002"}

    def test_requires_auth(self, client: TestClient):
        res = client.get(f"/taxii2/{_API_ROOT}/collections/{_JVN_COLLECTION_ID}/objects/")
        assert res.status_code == 403


class TestGetObjectJvn:
    def test_returns_matching_object(self, client: TestClient, db_session: Session, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        _make_jvn_vuln(db_session, jvndb_id="JVNDB-2026-300001")
        object_id = jvn_stix_vulnerability_id("JVNDB-2026-300001")

        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/{_JVN_COLLECTION_ID}/objects/{object_id}/",
            headers=_HEADERS,
        )
        assert res.status_code == 200
        objects = res.json()["objects"]
        assert len(objects) == 1
        assert objects[0]["name"] == "JVNDB-2026-300001"

    def test_404_for_unknown_object(self, client: TestClient, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/{_JVN_COLLECTION_ID}/objects/"
            "vulnerability--00000000-0000-0000-0000-000000000000/",
            headers=_HEADERS,
        )
        assert res.status_code == 404
