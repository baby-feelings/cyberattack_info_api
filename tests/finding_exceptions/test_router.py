"""/api/exceptions（登録・解除・一覧・VEX・手動実行）と、検知一覧・SBOM への反映のテスト。"""
import os
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.auth.session import create_session_token  # noqa: E402
from app.codescan.models import CodeFinding  # noqa: E402
from app.depscan.models import DependencyFinding  # noqa: E402
from app.finding_exceptions.models import FindingException  # noqa: E402

HEADERS = {"X-API-KEY": "test-api-key-for-pytest"}
NOW = datetime.now(UTC)
KEY = "npm|lodash|GHSA-1"


def _dep(repo="alice/api", osv="GHSA-1", resolved=False, fixed=None):
    return DependencyFinding(
        repo_full_name=repo, ecosystem="npm", package_name="lodash", installed_version="4.0.0",
        osv_id=osv, severity="HIGH", summary="s", fixed_versions=fixed or [],
        cve_ids=["CVE-2026-0001"], manifest_path="package-lock.json", detected_at=NOW,
        resolved_at=NOW if resolved else None,
    )


def _code(repo="alice/api", line=3):
    return CodeFinding(
        repo_full_name=repo, file_path=".github/workflows/ci.yml", line_start=line,
        line_end=line, rule_id="zizmor:artipacked", message="m", severity="WARNING",
        cwe_ids=[], owasp_categories=[], code_snippet="x", tool="zizmor", detected_at=NOW,
    )


def _body(**kwargs):
    body = {
        "kind": "dependency", "repo_full_name": "alice/api", "finding_key": KEY,
        "status": "accepted", "reason": "修正版が無い",
        "expires_at": (NOW + timedelta(days=30)).isoformat(),
    }
    body.update(kwargs)
    return body


def _session(user):
    """ログイン済みユーザーのセッショントークン（署名の鍵は、テストの環境変数の値）。"""
    return {"Authorization": f"Bearer {create_session_token(user)}"}


def _post(client, body, headers=HEADERS):
    with patch("app.finding_exceptions.router.sync_issues_after_change") as sync:
        res = client.post("/api/exceptions", json=body, headers=headers)
    return res, sync


class TestCreate:
    def test_requires_authentication(self, client):
        assert client.post("/api/exceptions", json=_body()).status_code in (401, 403)

    def test_accepts_a_finding_and_records_the_approver(self, client, db_session):
        db_session.add(_dep())
        db_session.commit()

        res, sync = _post(client, _body())

        assert res.status_code == 201
        body = res.json()
        assert (body["status"], body["finding_key"], body["ended_at"]) == ("accepted", KEY, None)
        # API キー認証の承認者は、管理者
        assert body["approver"] == "test-github-user"
        # 受容のあと、Issue の整合（有効な検知が0件なら閉じる）をバックグラウンドで行う
        sync.assert_called_once()
        assert sync.call_args.kwargs == {"accepted": True}

    def test_the_session_user_becomes_the_approver(self, client, db_session):
        db_session.add(_dep())
        db_session.commit()

        res, _ = _post(client, _body(), _session("alice"))

        assert res.status_code == 201
        assert res.json()["approver"] == "alice"

    def test_cannot_manage_other_users_repositories(self, client, db_session):
        db_session.add(_dep(repo="bob/app"))
        db_session.commit()

        res, sync = _post(client, _body(repo_full_name="bob/app"), _session("alice"))

        assert res.status_code == 403
        assert db_session.query(FindingException).count() == 0
        sync.assert_not_called()

    def test_unknown_finding_is_404(self, client):
        res, _ = _post(client, _body())
        assert res.status_code == 404

    def test_acceptance_requires_an_expiry(self, client, db_session):
        db_session.add(_dep())
        db_session.commit()
        res, _ = _post(client, _body(expires_at=None))
        assert res.status_code == 422
        assert "期限" in res.json()["detail"]

    def test_expiry_must_be_in_the_future_and_within_the_limit(self, client, db_session):
        db_session.add(_dep())
        db_session.commit()
        past, _ = _post(client, _body(expires_at=(NOW - timedelta(days=1)).isoformat()))
        far, _ = _post(client, _body(expires_at=(NOW + timedelta(days=400)).isoformat()))

        assert past.status_code == 422
        assert far.status_code == 422
        assert "365" in far.json()["detail"]

    def test_naive_expiry_is_treated_as_utc(self, client, db_session):
        db_session.add(_dep())
        db_session.commit()
        naive = (NOW + timedelta(days=5)).replace(tzinfo=None).isoformat()

        res, _ = _post(client, _body(expires_at=naive))

        assert res.status_code == 201

    def test_false_positive_and_not_affected_need_no_expiry(self, client, db_session):
        db_session.add(_dep())
        db_session.commit()

        res, _ = _post(client, _body(status="false_positive", expires_at=None))

        assert res.status_code == 201
        assert res.json()["expires_at"] is None

    def test_blank_reason_is_rejected(self, client, db_session):
        db_session.add(_dep())
        db_session.commit()
        res, _ = _post(client, _body(reason="   "))
        assert res.status_code == 422

    def test_registering_again_updates_the_active_exception(self, client, db_session):
        db_session.add(_dep())
        db_session.commit()

        first, _ = _post(client, _body(reason="最初"))
        second, _ = _post(client, _body(reason="更新"))

        assert first.json()["id"] == second.json()["id"]
        assert db_session.query(FindingException).count() == 1

    def test_code_findings_can_be_excepted_too(self, client, db_session):
        db_session.add(_code())
        db_session.commit()

        res, sync = _post(client, _body(
            kind="code", finding_key=".github/workflows/ci.yml|zizmor:artipacked",
            status="not_affected", expires_at=None,
        ))

        assert res.status_code == 201
        assert sync.call_args.args[0] == "code"


class TestListAndRevoke:
    def _seed(self, db_session):
        db_session.add_all([_dep(), _dep(repo="bob/app")])
        db_session.add_all([
            FindingException(kind="dependency", repo_full_name="alice/api", finding_key=KEY,
                             status="accepted", reason="r", approver="alice",
                             expires_at=NOW + timedelta(days=10)),
            FindingException(kind="dependency", repo_full_name="bob/app", finding_key=KEY,
                             status="accepted", reason="r", approver="bob",
                             expires_at=NOW + timedelta(days=10)),
            FindingException(kind="code", repo_full_name="alice/api", finding_key="f|r",
                             status="false_positive", reason="r", approver="alice",
                             ended_at=NOW, ended_reason="revoked"),
        ])
        db_session.commit()

    def test_lists_active_exceptions_by_default(self, client, db_session):
        self._seed(db_session)

        body = client.get("/api/exceptions", headers=HEADERS).json()

        assert body["total"] == 2
        assert {e["repo_full_name"] for e in body["data"]} == {"alice/api", "bob/app"}

    def test_can_include_ended_and_filter(self, client, db_session):
        self._seed(db_session)

        everything = client.get("/api/exceptions?include_ended=true", headers=HEADERS).json()
        only_code = client.get(
            "/api/exceptions?include_ended=true&kind=code", headers=HEADERS,
        ).json()
        by_owner = client.get("/api/exceptions?owner=bob", headers=HEADERS).json()

        assert everything["total"] == 3
        assert only_code["total"] == 1
        assert [e["repo_full_name"] for e in by_owner["data"]] == ["bob/app"]

    def test_session_user_sees_only_own_exceptions(self, client, db_session):
        self._seed(db_session)

        body = client.get("/api/exceptions?owner=bob", headers=_session("alice")).json()

        assert [e["repo_full_name"] for e in body["data"]] == ["alice/api"]

    def test_revoke_ends_the_exception_and_restores_the_issue(self, client, db_session):
        self._seed(db_session)
        exc_id = db_session.query(FindingException).filter_by(approver="alice",
                                                              kind="dependency").one().id

        with patch("app.finding_exceptions.router.sync_issues_after_change") as sync:
            res = client.delete(f"/api/exceptions/{exc_id}", headers=_session("alice"))

        assert res.status_code == 200
        assert (res.json()["ended_reason"], res.json()["ended_at"] is not None) == ("revoked", True)
        assert sync.call_args.kwargs == {"accepted": False}

    def test_cannot_revoke_other_users_exception_and_it_looks_missing(self, client, db_session):
        self._seed(db_session)
        bobs = db_session.query(FindingException).filter_by(approver="bob").one().id

        res = client.delete(f"/api/exceptions/{bobs}", headers=_session("alice"))

        assert res.status_code == 404

    def test_revoking_an_ended_exception_is_a_conflict(self, client, db_session):
        self._seed(db_session)
        ended = db_session.query(FindingException).filter(
            FindingException.ended_at.is_not(None)).one().id

        assert client.delete(f"/api/exceptions/{ended}", headers=HEADERS).status_code == 409
        assert client.delete("/api/exceptions/9999", headers=HEADERS).status_code == 404


class TestVex:
    def _seed(self, db_session):
        db_session.add_all([_dep(osv="GHSA-1"), _dep(osv="GHSA-2"), _dep(osv="GHSA-3")])
        db_session.add_all([
            FindingException(kind="dependency", repo_full_name="alice/api", finding_key=KEY,
                             status="accepted", reason="修正版が無い", approver="alice",
                             expires_at=NOW + timedelta(days=10)),
            FindingException(kind="dependency", repo_full_name="alice/api",
                             finding_key="npm|lodash|GHSA-2", status="not_affected",
                             reason="到達しない", approver="alice"),
            # 終了した例外は、出力しない
            FindingException(kind="dependency", repo_full_name="alice/api",
                             finding_key="npm|lodash|GHSA-3", status="accepted", reason="r",
                             approver="alice", ended_at=NOW, ended_reason="revoked"),
        ])
        db_session.commit()

    def test_openvex_maps_accepted_to_affected_and_not_affected(self, client, db_session):
        self._seed(db_session)

        res = client.get("/api/exceptions/vex?repo=alice/api", headers=HEADERS)

        assert res.status_code == 200
        assert res.headers["content-type"].startswith("application/vnd.openvex+json")
        doc = res.json()
        assert doc["@context"].startswith("https://openvex.dev/ns/")
        by_name = {s["vulnerability"]["name"]: s for s in doc["statements"]}
        assert set(by_name) == {"GHSA-1", "GHSA-2"}
        assert by_name["GHSA-1"]["status"] == "affected"
        assert "修正版が無い" in by_name["GHSA-1"]["action_statement"]
        assert by_name["GHSA-1"]["vulnerability"]["aliases"] == ["CVE-2026-0001"]
        assert by_name["GHSA-2"]["status"] == "not_affected"
        assert by_name["GHSA-2"]["impact_statement"] == "到達しない"
        assert by_name["GHSA-1"]["products"][0]["@id"] == "pkg:npm/lodash@4.0.0"

    def test_cyclonedx_vex_carries_the_analysis(self, client, db_session):
        self._seed(db_session)

        doc = client.get(
            "/api/exceptions/vex?repo=alice/api&format=cyclonedx", headers=HEADERS,
        ).json()

        by_id = {v["id"]: v for v in doc["vulnerabilities"]}
        assert by_id["GHSA-1"]["analysis"]["state"] == "exploitable"
        assert by_id["GHSA-1"]["analysis"]["response"] == ["will_not_fix"]
        assert by_id["GHSA-2"]["analysis"]["state"] == "not_affected"
        assert doc["bomFormat"] == "CycloneDX"

    def test_false_positive_is_exported_as_not_affected(self, client, db_session):
        db_session.add(_dep())
        db_session.add(FindingException(
            kind="dependency", repo_full_name="alice/api", finding_key=KEY,
            status="false_positive", reason="誤検知", approver="alice"))
        db_session.commit()

        doc = client.get("/api/exceptions/vex?repo=alice/api&format=cyclonedx",
                         headers=HEADERS).json()

        assert doc["vulnerabilities"][0]["analysis"]["state"] == "false_positive"

    def test_only_the_owner_can_export(self, client, db_session):
        self._seed(db_session)
        res = client.get("/api/exceptions/vex?repo=alice/api", headers=_session("bob"))
        assert res.status_code == 403

    def test_empty_when_there_is_no_exception(self, client):
        doc = client.get("/api/exceptions/vex?repo=alice/api", headers=HEADERS).json()
        assert doc["statements"] == []


class TestReflectedInFindingApis:
    def _seed(self, db_session):
        db_session.add_all([_dep(osv="GHSA-1"), _dep(osv="GHSA-2"), _code(line=1), _code(line=2)])
        db_session.add_all([
            FindingException(kind="dependency", repo_full_name="alice/api", finding_key=KEY,
                             status="accepted", reason="修正版が無い", approver="alice",
                             expires_at=NOW + timedelta(days=10)),
            FindingException(kind="code", repo_full_name="alice/api",
                             finding_key=".github/workflows/ci.yml|zizmor:artipacked",
                             status="not_affected", reason="意図的", approver="alice"),
        ])
        db_session.commit()

    def test_depscan_list_shows_the_exception_but_keeps_the_finding(self, client, db_session):
        self._seed(db_session)

        data = client.get("/api/depscan", headers=HEADERS).json()["data"]

        by_osv = {d["osv_id"]: d for d in data}
        assert by_osv["GHSA-1"]["exception"]["status"] == "accepted"
        assert by_osv["GHSA-1"]["exception"]["reason"] == "修正版が無い"
        assert by_osv["GHSA-1"]["exception_key"] == KEY
        assert by_osv["GHSA-2"]["exception"] is None

    def test_depscan_stats_leave_out_excepted_findings(self, client, db_session):
        self._seed(db_session)

        stats = client.get("/api/depscan/stats", headers=HEADERS).json()

        assert stats["total"] == 1

    def test_codescan_list_and_stats(self, client, db_session):
        self._seed(db_session)

        data = client.get("/api/codescan", headers=HEADERS).json()["data"]
        stats = client.get("/api/codescan/stats", headers=HEADERS).json()

        assert len(data) == 2
        assert all(d["exception"]["status"] == "not_affected" for d in data)
        assert data[0]["exception_key"] == ".github/workflows/ci.yml|zizmor:artipacked"
        # 同じファイル・ルールは、行が違っても、まとめて例外になる
        assert stats["total"] == 0

    def test_expired_exception_brings_the_finding_back(self, client, db_session):
        self._seed(db_session)
        row = db_session.query(FindingException).filter_by(kind="dependency").one()
        row.expires_at = NOW - timedelta(days=1)
        db_session.commit()

        assert client.get("/api/depscan/stats", headers=HEADERS).json()["total"] == 2

    def test_sbom_embeds_the_vex_analysis(self, client, db_session):
        self._seed(db_session)

        sbom = client.get("/api/depscan/export?repo=alice/api", headers=HEADERS).json()

        by_id = {v["id"]: v for v in sbom["vulnerabilities"]}
        assert by_id["GHSA-1"]["analysis"]["state"] == "exploitable"
        assert "analysis" not in by_id["GHSA-2"]


class TestTriggerLifecycle:
    def test_requires_the_admin_api_key(self, client):
        assert client.post("/admin/exception-lifecycle").status_code in (401, 403)

    def test_starts_the_job_in_the_background(self, client):
        with patch("app.finding_exceptions.router.run_in_background") as run:
            res = client.post("/admin/exception-lifecycle", headers=HEADERS)

        assert res.status_code == 202
        assert run.call_args[0][0] == "EXCEPTION_LIFECYCLE"
