"""app.github_alerts（取得・保存・突き合わせ・API・通知・ジョブ。Issue #402）のテスト。"""
# ruff: noqa: E501 - 試験データの表（1行に1件）を、読みやすい形で並べるため
import os
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import httpx

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.auth.session import create_session_token  # noqa: E402
from app.core.notifications.github_alerts import GithubAlertNotifier  # noqa: E402
from app.depscan.models import DependencyFinding  # noqa: E402
from app.github_alerts import client  # noqa: E402
from app.github_alerts.crawler import _GithubAlertJob  # noqa: E402
from app.github_alerts.models import GithubAlert, GithubAlertSource  # noqa: E402
from app.github_alerts.repository import GithubAlertRepository, dependabot_vs_depscan  # noqa: E402

HEADERS = {"X-API-KEY": "test-api-key-for-pytest"}
NOW = datetime(2026, 10, 31, tzinfo=UTC)

SECRET_ITEM = {
    "number": 4, "html_url": "https://github.com/o/r/security/secret-scanning/4",
    "created_at": "2026-10-01T00:00:00Z", "secret_type": "aws_access_key_id",
    "secret_type_display_name": "AWS Access Key ID", "validity": "active",
    "publicly_leaked": True, "push_protection_bypassed": False,
    # 値そのもの。保存・通知しては、いけない
    "secret": "AKIA-REAL-SECRET-VALUE",
}
DEPENDABOT_ITEM = {
    "number": 7, "html_url": "https://github.com/o/r/security/dependabot/7",
    "created_at": "2026-10-02T00:00:00Z",
    "dependency": {"package": {"ecosystem": "npm", "name": "lodash"}},
    "security_advisory": {"ghsa_id": "GHSA-1", "cve_id": "CVE-1", "severity": "high",
                          "summary": "Prototype pollution"},
    "security_vulnerability": {"first_patched_version": {"identifier": "4.17.21"}},
}
CODE_ITEM = {
    "number": 9, "html_url": "https://github.com/o/r/security/code-scanning/9",
    "created_at": "2026-10-03T00:00:00Z",
    "rule": {"id": "js/xss", "description": "XSS", "security_severity_level": "critical"},
    "most_recent_instance": {"location": {"path": "src/a.js"}}, "tool": {"name": "CodeQL"},
}


def _alert(kind="dependabot", repo="u/app", number=1, **detail):
    return {
        "kind": kind, "repo_full_name": repo, "number": number, "severity": "HIGH",
        "title": "t", "html_url": "https://x/1", "detail": detail, "detected_at": NOW,
    }


class TestNormalize:
    def test_secret_never_carries_the_secret_value(self):
        alert = client.normalize_secret("o/r", SECRET_ITEM)

        assert alert["severity"] == "CRITICAL"  # 有効なシークレットは、緊急
        assert alert["title"] == "AWS Access Key ID（有効性: active）"
        assert alert["detail"]["publicly_leaked"] is True
        assert "AKIA-REAL-SECRET-VALUE" not in repr(alert)

    def test_inactive_or_unknown_secret_is_high(self):
        assert client.normalize_secret("o/r", {**SECRET_ITEM, "validity": "inactive"})["severity"] == "HIGH"
        item = {k: v for k, v in SECRET_ITEM.items() if k != "validity"}
        assert client.normalize_secret("o/r", item)["detail"]["validity"] == "unknown"

    def test_dependabot_fields(self):
        alert = client.normalize_dependabot("o/r", DEPENDABOT_ITEM)

        assert alert["severity"] == "HIGH"
        assert alert["detail"] == {
            "ecosystem": "npm", "package": "lodash", "ghsa_id": "GHSA-1", "cve_id": "CVE-1",
            "fixed_version": "4.17.21",
        }

    def test_code_scanning_fields_and_missing_values(self):
        alert = client.normalize_code("o/r", CODE_ITEM)
        assert (alert["severity"], alert["detail"]["path"], alert["detail"]["tool"]) == (
            "CRITICAL", "src/a.js", "CodeQL")
        bare = client.normalize_code("o/r", {"number": 1, "html_url": "u", "created_at": None})
        assert bare["title"] == "code scanning alert" and bare["severity"] is None


class TestFetchAlerts:
    def _repo(self, *responses):
        api = MagicMock()
        api.get.side_effect = list(responses)
        repo = MagicMock()
        repo.full_name = "o/r"
        repo.path.side_effect = lambda s: f"/repos/o/r{s}"
        repo.api.return_value.__enter__.return_value = api
        return repo, api

    @staticmethod
    def _resp(status=200, items=None):
        resp = MagicMock()
        resp.status_code = status
        resp.json.return_value = items or []
        resp.raise_for_status.side_effect = (
            httpx.HTTPStatusError("x", request=MagicMock(), response=resp) if status >= 500 else None
        )
        return resp

    def test_returns_normalized_open_alerts(self):
        repo, api = self._repo(self._resp(items=[DEPENDABOT_ITEM]))

        alerts, reason = client.fetch_alerts(repo, "dependabot")

        assert reason is None and [a["number"] for a in alerts] == [7]
        assert api.get.call_args.args[0] == "/repos/o/r/dependabot/alerts"
        assert api.get.call_args.kwargs["params"]["state"] == "open"

    def test_follows_pages_until_a_short_page(self):
        full = [dict(DEPENDABOT_ITEM, number=i) for i in range(100)]
        repo, api = self._repo(self._resp(items=full), self._resp(items=[DEPENDABOT_ITEM]))

        alerts, _ = client.fetch_alerts(repo, "dependabot")

        assert len(alerts) == 101 and api.get.call_count == 2

    def test_disabled_or_forbidden_is_unavailable_not_empty(self):
        for status in (403, 404):
            repo, _ = self._repo(self._resp(status=status))
            alerts, reason = client.fetch_alerts(repo, "secret")
            assert alerts is None and f"HTTP {status}" in reason

    def test_server_errors_are_raised(self):
        repo, _ = self._repo(self._resp(status=500))
        try:
            client.fetch_alerts(repo, "code")
        except httpx.HTTPStatusError:
            return
        raise AssertionError("expected an error")

    def test_is_unavailable_error(self):
        assert client.is_unavailable_error(httpx.ConnectError("x")) is True
        assert client.is_unavailable_error(ValueError("x")) is False


class TestRepository:
    def test_sync_inserts_updates_and_resolves(self, db_session):
        repo = GithubAlertRepository(db_session)
        first = repo.sync("dependabot", "u/app", [_alert(number=1), _alert(number=2)])
        second = repo.sync("dependabot", "u/app", [{**_alert(number=2), "title": "new"}, _alert(number=3)])

        assert len(first) == 2 and [a.number for a in second] == [3]
        rows = {a.number: a for a in db_session.query(GithubAlert).all()}
        assert rows[1].resolved_at is not None      # GitHub 側で解決された
        assert rows[2].title == "new" and rows[2].resolved_at is None
        assert rows[3].resolved_at is None

    def test_a_reopened_alert_is_unresolved_again(self, db_session):
        repo = GithubAlertRepository(db_session)
        repo.sync("code", "u/app", [_alert("code")])
        repo.sync("code", "u/app", [])
        repo.sync("code", "u/app", [_alert("code")])

        assert db_session.query(GithubAlert).one().resolved_at is None

    def test_unavailable_is_recorded_without_touching_existing_alerts(self, db_session):
        repo = GithubAlertRepository(db_session)
        repo.sync("secret", "u/app", [_alert("secret")])
        repo.record_unavailable("secret", "u/app", "機能が無効（HTTP 404）")

        assert db_session.query(GithubAlert).one().resolved_at is None
        source = db_session.query(GithubAlertSource).one()
        assert (source.status, source.reason) == ("unavailable", "機能が無効（HTTP 404）")
        # 取得できた場合は、利用可能に戻る
        repo.sync("secret", "u/app", [])
        assert db_session.query(GithubAlertSource).one().status == "available"


class TestCompare:
    def test_splits_both_only_github_and_only_depscan(self, db_session):
        db_session.add_all([
            GithubAlert(**_alert(number=1, ecosystem="npm", package="lodash", ghsa_id="GHSA-1")),
            GithubAlert(**_alert(number=2, ecosystem="npm", package="express", ghsa_id="GHSA-2")),
            GithubAlert(**{**_alert(number=3, ecosystem="npm", package="x", ghsa_id="GHSA-3"),
                           "resolved_at": NOW}),
            DependencyFinding(
                repo_full_name="u/app", ecosystem="npm", package_name="Lodash", installed_version="1",
                osv_id="GHSA-1", severity="HIGH", summary="s", fixed_versions=[], cve_ids=[],
                manifest_path="p", detected_at=NOW),
            DependencyFinding(
                repo_full_name="u/app", ecosystem="PyPI", package_name="requests", installed_version="1",
                osv_id="GHSA-9", severity="LOW", summary="s", fixed_versions=[], cve_ids=[],
                manifest_path="p", detected_at=NOW),
        ])
        db_session.commit()

        result = dependabot_vs_depscan(db_session)

        assert [r["advisory_id"] for r in result["both"]] == ["GHSA-1"]
        assert [r["advisory_id"] for r in result["only_github"]] == ["GHSA-2"]
        assert [r["advisory_id"] for r in result["only_depscan"]] == ["GHSA-9"]

    def test_can_be_limited_to_an_owner(self, db_session):
        db_session.add(GithubAlert(**_alert(repo="bob/app", ecosystem="npm", package="a", ghsa_id="G")))
        db_session.commit()

        assert dependabot_vs_depscan(db_session, "alice")["only_github"] == []
        assert len(dependabot_vs_depscan(db_session, "bob")["only_github"]) == 1


class TestApi:
    def _seed(self, db_session):
        db_session.add_all([
            GithubAlert(**_alert("secret", "alice/api", 1)),
            GithubAlert(**{**_alert("code", "alice/api", 2), "resolved_at": NOW}),
            GithubAlert(**_alert("dependabot", "bob/app", 3, ecosystem="npm", package="a", ghsa_id="G")),
            GithubAlertSource(kind="secret", repo_full_name="alice/web", status="unavailable",
                              reason="HTTP 404", checked_at=NOW),
            GithubAlertSource(kind="code", repo_full_name="bob/app", status="available",
                              checked_at=NOW),
        ])
        db_session.commit()

    def test_requires_authentication(self, client):
        assert client.get("/api/github-alerts").status_code in (401, 403)

    def test_lists_open_alerts_and_unavailable_sources(self, client, db_session):
        self._seed(db_session)

        body = client.get("/api/github-alerts", headers=HEADERS).json()

        assert body["total"] == 2
        assert {a["kind"] for a in body["data"]} == {"secret", "dependabot"}
        assert [(u["repo_full_name"], u["kind"]) for u in body["unavailable"]] == [("alice/web", "secret")]

    def test_filters_and_includes_resolved(self, client, db_session):
        self._seed(db_session)

        only_code = client.get("/api/github-alerts?kind=code&resolved=true", headers=HEADERS).json()
        by_repo = client.get("/api/github-alerts?repo=bob/app", headers=HEADERS).json()

        assert only_code["total"] == 1 and only_code["data"][0]["resolved_at"] is not None
        assert [a["repo_full_name"] for a in by_repo["data"]] == ["bob/app"]

    def test_session_user_sees_only_own_repositories(self, client, db_session):
        self._seed(db_session)
        token = create_session_token("alice")

        body = client.get("/api/github-alerts", headers={"Authorization": f"Bearer {token}"}).json()

        assert {a["repo_full_name"] for a in body["data"]} == {"alice/api"}
        assert [u["repo_full_name"] for u in body["unavailable"]] == ["alice/web"]

    def test_compare_endpoint(self, client, db_session):
        self._seed(db_session)
        body = client.get("/api/github-alerts/compare", headers=HEADERS).json()
        assert [r["repo_full_name"] for r in body["only_github"]] == ["bob/app"]

    def test_manual_crawl_needs_the_admin_key_and_runs_in_background(self, client):
        assert client.post("/admin/github-alerts-crawl").status_code in (401, 403)
        with patch("app.github_alerts.router.run_in_background") as run:
            res = client.post("/admin/github-alerts-crawl?force=true", headers=HEADERS)
        assert res.status_code == 202 and run.call_args[0][0] == "GHALERT"


class TestNotifier:
    def _alerts(self, n=2):
        return [
            {"repo_full_name": "u/app", "title": f"AWS key {i}", "html_url": f"https://x/{i}",
             "severity": "HIGH" if i else "CRITICAL", "detail": {"publicly_leaked": i == 0}}
            for i in range(n)
        ]

    def test_has_content_only_with_alerts(self):
        assert GithubAlertNotifier([]).has_content() is False
        assert GithubAlertNotifier(self._alerts()).has_content() is True

    def test_message_puts_active_first_and_explains_revocation(self):
        message = GithubAlertNotifier(self._alerts(), recipients=["h"]).build_message()

        assert message.index("AWS key 0") < message.index("AWS key 1")
        assert "公開された可能性あり" in message
        assert "無効化・再発行" in message and "git filter-repo" in message

    def test_truncates_long_lists(self):
        message = GithubAlertNotifier(self._alerts(13), recipients=["h"]).build_message()
        assert "ほか 3件" in message

    def test_default_recipient_is_the_admin_only(self):
        with patch("app.core.notifications.recipients.resolve_admin_recipient",
                   return_value=["h"]) as admin:
            assert GithubAlertNotifier([]).default_recipients() == ["h"]
        admin.assert_called_once()


class TestJob:
    def _run(self, db_session, fetch, repos=({"full_name": "u/app"},)):
        job = _GithubAlertJob()
        counters = MagicMock(inserted=0, deleted=0, updated=0)
        with patch("app.github_alerts.crawler.list_target_repos", return_value=list(repos)), \
             patch("app.github_alerts.crawler.fetch_alerts", side_effect=fetch):
            job.execute(db_session, counters)
        return job, counters

    def test_stores_alerts_and_collects_new_secrets_for_notification(self, db_session):
        def fetch(repo, kind):
            return {"secret": [_alert("secret", number=1)], "dependabot": [], "code": []}[kind], None

        job, counters = self._run(db_session, fetch)

        assert counters.inserted == 1 and job.repos_scanned == 1
        assert [s["number"] for s in job.new_secret_snapshots] == [1]
        # 2回目は、既知のため、新規として通知しない
        job2, _ = self._run(db_session, fetch)
        assert job2.new_secret_snapshots == []

    def test_counts_resolved_and_unavailable_and_survives_http_errors(self, db_session):
        db_session.add(GithubAlert(**_alert("dependabot", number=5)))
        db_session.commit()

        def fetch(repo, kind):
            if kind == "dependabot":
                return [], None                    # 0 件 → 既存の1件は解決済み
            if kind == "secret":
                return None, "HTTP 404"            # 取得不可
            raise httpx.ConnectError("boom")       # 通信の失敗

        _, counters = self._run(db_session, fetch)

        assert counters.deleted == 1 and counters.updated == 2
        assert db_session.query(GithubAlertSource).filter_by(kind="secret").one().status == "unavailable"

    def test_after_success_notifies_only_new_secrets_and_never_fails(self):
        job = _GithubAlertJob()
        job.new_secret_snapshots = [_alert("secret")]
        with patch("app.github_alerts.crawler.GithubAlertNotifier") as notifier:
            notifier.return_value.send.return_value = True
            job.after_success(MagicMock(inserted=1, deleted=0, updated=0))
        assert notifier.call_args.args[0] == job.new_secret_snapshots

        with patch("app.github_alerts.crawler.GithubAlertNotifier", side_effect=RuntimeError("x")):
            job.after_success(MagicMock(inserted=1, deleted=0, updated=0))  # 例外を送出しない

    def test_result_and_entry_point(self):
        job = _GithubAlertJob()
        job.repos_scanned = 3
        assert job.result(MagicMock(inserted=1, deleted=2)) == (1, 2, 3)
        from app.github_alerts.crawler import fetch_and_store_github_alerts
        with patch("app.github_alerts.crawler._GithubAlertJob") as cls:
            cls.return_value.run.return_value = (0, 0, 0)
            assert fetch_and_store_github_alerts(force=True) == (0, 0, 0)
            cls.return_value.run.assert_called_once_with(force=True)
