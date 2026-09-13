"""app.kev.taxii（TAXII 2.1配信、Issue #134）のテスト。"""
from datetime import date, datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.kev.models import Vulnerability
from app.kev.stix import stix_vulnerability_id
from tests.conftest import TEST_API_KEY

_API_ROOT = "cyberattack-info-api"
_COLLECTION_ID = "d4d8f0c0-3f5f-5b1e-9c1a-6f6f6a6b6a6a"
_HEADERS = {"X-API-KEY": TEST_API_KEY}


def _make_vuln(db: Session, cve_id: str = "CVE-2026-00001", **kwargs) -> Vulnerability:
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
    def test_returns_kev_collection(self, client: TestClient, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        res = client.get(f"/taxii2/{_API_ROOT}/collections/", headers=_HEADERS)
        assert res.status_code == 200
        collections = res.json()["collections"]
        assert len(collections) == 1
        assert collections[0]["id"] == _COLLECTION_ID
        assert collections[0]["can_write"] is False

    def test_404_for_unknown_root(self, client: TestClient, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        res = client.get("/taxii2/unknown-root/collections/", headers=_HEADERS)
        assert res.status_code == 404


class TestGetCollection:
    def test_returns_collection_info(self, client: TestClient, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/{_COLLECTION_ID}/", headers=_HEADERS,
        )
        assert res.status_code == 200
        assert res.json()["id"] == _COLLECTION_ID

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
            f"/taxii2/unknown-root/collections/{_COLLECTION_ID}/", headers=_HEADERS,
        )
        assert res.status_code == 404


class TestListObjects:
    def test_returns_stix_objects(self, client: TestClient, db_session: Session, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        _make_vuln(db_session, cve_id="CVE-2026-10001")
        _make_vuln(db_session, cve_id="CVE-2026-10002")

        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/{_COLLECTION_ID}/objects/", headers=_HEADERS,
        )
        assert res.status_code == 200
        objects = res.json()["objects"]
        assert len(objects) == 2
        assert all(obj["type"] == "vulnerability" for obj in objects)

    def test_filters_by_added_after(self, client: TestClient, db_session: Session, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        old = _make_vuln(db_session, cve_id="CVE-2026-20001")
        old.updated_at = datetime.now(timezone.utc) - timedelta(days=10)
        db_session.commit()
        _make_vuln(db_session, cve_id="CVE-2026-20002")

        cutoff = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/{_COLLECTION_ID}/objects/",
            params={"added_after": cutoff},
            headers=_HEADERS,
        )
        names = {obj["name"] for obj in res.json()["objects"]}
        assert names == {"CVE-2026-20002"}

    def test_respects_limit(self, client: TestClient, db_session: Session, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        for i in range(3):
            _make_vuln(db_session, cve_id=f"CVE-2026-3000{i}")

        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/{_COLLECTION_ID}/objects/?limit=2",
            headers=_HEADERS,
        )
        assert len(res.json()["objects"]) == 2

    def test_requires_auth(self, client: TestClient):
        res = client.get(f"/taxii2/{_API_ROOT}/collections/{_COLLECTION_ID}/objects/")
        assert res.status_code == 403


class TestGetObject:
    def test_returns_matching_object(self, client: TestClient, db_session: Session, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        _make_vuln(db_session, cve_id="CVE-2026-40001")
        object_id = stix_vulnerability_id("CVE-2026-40001")

        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/{_COLLECTION_ID}/objects/{object_id}/",
            headers=_HEADERS,
        )
        assert res.status_code == 200
        objects = res.json()["objects"]
        assert len(objects) == 1
        assert objects[0]["name"] == "CVE-2026-40001"

    def test_404_for_unknown_object(self, client: TestClient, monkeypatch):
        monkeypatch.setattr("app.core.auth.settings.API_KEY", TEST_API_KEY)
        res = client.get(
            f"/taxii2/{_API_ROOT}/collections/{_COLLECTION_ID}/objects/"
            "vulnerability--00000000-0000-0000-0000-000000000000/",
            headers=_HEADERS,
        )
        assert res.status_code == 404
