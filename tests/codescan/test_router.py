"""GET /api/codescan・/api/codescan/stats・POST /admin/codescan-crawl のテスト。"""
from datetime import datetime, timezone
from unittest.mock import patch

from app.codescan.models import CodeFinding
from tests.conftest import TEST_API_KEY

HEADERS = {"X-API-KEY": TEST_API_KEY}
_NOW = datetime.now(timezone.utc)


def _make_finding(db_session, **kwargs) -> CodeFinding:
    defaults = {
        "repo_full_name": "baby-feelings/baby_grow",
        "file_path": "app/main.py",
        "line_start": 10,
        "line_end": 10,
        "rule_id": "python.lang.security.audit.hardcoded-password",
        "message": "Hardcoded password detected",
        "severity": "ERROR",
        "cwe_ids": ["CWE-798"],
        "owasp_categories": [],
        "code_snippet": 'PASSWORD = "hunter2"',
        "cvss_score": 7.4,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "detected_at": _NOW,
        "resolved_at": None,
    }
    defaults.update(kwargs)
    record = CodeFinding(**defaults)
    db_session.add(record)
    db_session.commit()
    return record


class TestListCodescan:
    def test_requires_auth(self, client):
        resp = client.get("/api/codescan")
        assert resp.status_code == 403

    def test_returns_findings(self, client, db_session):
        _make_finding(db_session)
        resp = client.get("/api/codescan", headers=HEADERS)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert body["data"][0]["repo_full_name"] == "baby-feelings/baby_grow"
        assert body["data"][0]["cvss_score"] == 7.4

    def test_filters_by_repo(self, client, db_session):
        _make_finding(db_session, repo_full_name="a/x")
        _make_finding(db_session, repo_full_name="b/y", rule_id="other.rule")
        resp = client.get("/api/codescan", params={"repo": "a/x"}, headers=HEADERS)
        assert resp.json()["total"] == 1

    def test_filters_by_owner(self, client, db_session):
        _make_finding(db_session, repo_full_name="baby-feelings/a")
        _make_finding(db_session, repo_full_name="other/b", rule_id="other.rule")
        resp = client.get("/api/codescan", params={"owner": "baby-feelings"}, headers=HEADERS)
        assert resp.json()["total"] == 1

    def test_filters_by_severity(self, client, db_session):
        _make_finding(db_session, severity="ERROR")
        _make_finding(db_session, severity="INFO", rule_id="other.rule")
        resp = client.get("/api/codescan", params={"severity": "error"}, headers=HEADERS)
        assert resp.json()["total"] == 1

    def test_filters_by_resolved(self, client, db_session):
        _make_finding(db_session, resolved_at=_NOW)
        _make_finding(db_session, resolved_at=None, rule_id="other.rule")
        resp = client.get("/api/codescan", params={"resolved": True}, headers=HEADERS)
        assert resp.json()["total"] == 1

    def test_filters_by_min_cvss(self, client, db_session):
        _make_finding(db_session, cvss_score=9.0)
        _make_finding(db_session, cvss_score=2.0, rule_id="other.rule")
        resp = client.get("/api/codescan", params={"min_cvss": 7.0}, headers=HEADERS)
        assert resp.json()["total"] == 1

    def test_public_api_key_is_accepted(self, client, db_session):
        with patch("app.core.auth.settings.PUBLIC_API_KEY", "public-key-123"):
            resp = client.get("/api/codescan", headers={"X-API-KEY": "public-key-123"})
        assert resp.status_code == 200


class TestCodescanStats:
    def test_returns_stats_for_unresolved_only(self, client, db_session):
        _make_finding(db_session, resolved_at=None, severity="ERROR")
        _make_finding(db_session, resolved_at=_NOW, rule_id="other.rule", severity="INFO")
        resp = client.get("/api/codescan/stats", headers=HEADERS)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert body["repos"][0]["repo_full_name"] == "baby-feelings/baby_grow"
        assert body["severities"][0]["severity"] == "ERROR"


class TestTriggerCodescanCrawl:
    def test_requires_api_key(self, client):
        resp = client.post("/admin/codescan-crawl")
        assert resp.status_code == 403

    def test_starts_background_scan(self, client):
        with patch("app.codescan.router.run_in_background") as mock_bg:
            resp = client.post("/admin/codescan-crawl", headers=HEADERS)
        assert resp.status_code == 202
        mock_bg.assert_called_once()
        assert mock_bg.call_args[0][0] == "CODESCAN"
