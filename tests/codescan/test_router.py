"""GET /api/codescan・/api/codescan/stats・POST /admin/codescan-crawl のテスト。

CODESCAN は GitHub ログイン必須化（Issue #219）により、require_public_api_key
から require_api_key_or_session（X-API-KEY またはセッション JWT）に変更された。
"""
from datetime import UTC, datetime
from unittest.mock import patch

from app.auth.session import create_session_token
from app.codescan.models import CodeFinding
from tests.conftest import TEST_API_KEY

HEADERS = {"X-API-KEY": TEST_API_KEY}
_SESSION_HEADERS = {"Authorization": f"Bearer {create_session_token('octocat')}"}
_NOW = datetime.now(UTC)


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
        "tool": "semgrep",
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
        assert body["data"][0]["tool"] == "semgrep"

    def test_session_token_sees_only_own_repos(self, client, db_session):
        # セッション認証時は、ログインユーザー（octocat）本人が所有するリポジトリのみ見える。
        # 他のユーザー（baby-feelings）のリポジトリの検知結果は閲覧できない
        _make_finding(db_session, repo_full_name="octocat/mine")
        _make_finding(
            db_session, repo_full_name="baby-feelings/other-repo", rule_id="other.rule",
        )
        resp = client.get("/api/codescan", headers=_SESSION_HEADERS)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert body["data"][0]["repo_full_name"] == "octocat/mine"

    def test_session_token_cannot_bypass_owner_with_owner_param(self, client, db_session):
        _make_finding(db_session, repo_full_name="baby-feelings/other-repo")
        resp = client.get(
            "/api/codescan", params={"owner": "baby-feelings"}, headers=_SESSION_HEADERS,
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    def test_session_token_cannot_query_other_users_repo(self, client, db_session):
        _make_finding(db_session, repo_full_name="baby-feelings/other-repo")
        resp = client.get(
            "/api/codescan", params={"repo": "baby-feelings/other-repo"},
            headers=_SESSION_HEADERS,
        )
        assert resp.status_code == 403

    def test_invalid_session_token_and_no_api_key_returns_403(self, client):
        resp = client.get(
            "/api/codescan", headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert resp.status_code == 403

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

    def test_public_api_key_alone_is_rejected(self, client, db_session):
        # ログイン必須化（Issue #219）により、読み取り専用の PUBLIC_API_KEY では
        # アクセスできない（require_api_key_or_session は X-API-KEY または
        # セッションJWTのみを受け付ける。DEPSCANと同じ方針）
        with patch("app.auth.api_key.settings.PUBLIC_API_KEY", "public-key-123"):
            resp = client.get("/api/codescan", headers={"X-API-KEY": "public-key-123"})
        assert resp.status_code == 403


class TestCodescanStats:
    def test_requires_auth(self, client):
        resp = client.get("/api/codescan/stats")
        assert resp.status_code == 403

    def test_returns_stats_for_unresolved_only(self, client, db_session):
        _make_finding(db_session, resolved_at=None, severity="ERROR")
        _make_finding(db_session, resolved_at=_NOW, rule_id="other.rule", severity="INFO")
        resp = client.get("/api/codescan/stats", headers=HEADERS)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert body["repos"][0]["repo_full_name"] == "baby-feelings/baby_grow"
        assert body["severities"][0]["severity"] == "ERROR"

    def test_excepted_findings_are_counted_separately_per_repo(self, client, db_session):
        """例外の検知は「対応が必要」の件数に含めず、リポジトリ別に別の件数で返す。
        例外だけのリポジトリも一覧に残す（画面の一覧と食い違わないようにするため）。"""
        from datetime import timedelta

        from app.finding_exceptions.models import FindingException

        # baby_grow: 対応が必要1件＋例外1件／other: 例外のみ1件
        _make_finding(db_session, file_path="a.py", rule_id="rule.a")
        _make_finding(db_session, file_path="b.py", rule_id="rule.b")
        _make_finding(
            db_session, repo_full_name="baby-feelings/other", file_path="c.py", rule_id="rule.c",
        )
        for repo, key in (
            ("baby-feelings/baby_grow", "b.py|rule.b"),
            ("baby-feelings/other", "c.py|rule.c"),
        ):
            db_session.add(FindingException(
                kind="code", repo_full_name=repo, finding_key=key, status="not_affected",
                reason="意図的", approver="owner", expires_at=_NOW + timedelta(days=5),
            ))
        db_session.commit()

        body = client.get("/api/codescan/stats", headers=HEADERS).json()

        assert body["total"] == 1
        assert body["excepted_total"] == 2
        repos = {r["repo_full_name"]: (r["count"], r["excepted_count"]) for r in body["repos"]}
        assert repos == {"baby-feelings/baby_grow": (1, 1), "baby-feelings/other": (0, 1)}
        # 対応が必要な件数の多いリポジトリが先頭に並ぶ
        assert body["repos"][0]["repo_full_name"] == "baby-feelings/baby_grow"

    def test_session_token_counts_only_own_repos(self, client, db_session):
        _make_finding(db_session, repo_full_name="octocat/mine", resolved_at=None)
        _make_finding(
            db_session, repo_full_name="baby-feelings/other-repo", rule_id="other.rule",
            resolved_at=None,
        )
        resp = client.get("/api/codescan/stats", headers=_SESSION_HEADERS)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert body["repos"][0]["repo_full_name"] == "octocat/mine"


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

    def test_force_query_param_is_passed_through(self, client):
        """?force=true が fetch_and_scan_code(force=True) に渡ること（Issue #239）。"""
        with patch(
            "app.codescan.router.run_in_background", side_effect=lambda name, fn: fn(),
        ), patch(
            "app.codescan.router.fetch_and_scan_code", return_value=(0, 0, 0),
        ) as mock_fetch:
            resp = client.post("/admin/codescan-crawl?force=true", headers=HEADERS)
        assert resp.status_code == 202
        mock_fetch.assert_called_once_with(force=True)
