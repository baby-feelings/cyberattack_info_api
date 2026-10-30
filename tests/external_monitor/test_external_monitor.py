"""app.external_monitor（点検・SSRF 対策・対象の検出・ジョブ・API・通知。Issue #401）のテスト。"""
# ruff: noqa: E501 - 試験データの表（1行に1件）を、読みやすい形で並べるため
import os
import socket
import ssl
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import httpx

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.auth.session import create_session_token  # noqa: E402
from app.core.notifications.site_alerts import SiteAlertNotifier  # noqa: E402
from app.external_monitor import probes, targets  # noqa: E402
from app.external_monitor.crawler import _SiteMonitorJob, check_target  # noqa: E402
from app.external_monitor.models import SiteCheck  # noqa: E402
from app.external_monitor.targets import Target  # noqa: E402

HEADERS = {"X-API-KEY": "test-api-key-for-pytest"}
NOW = datetime(2026, 10, 31, tzinfo=UTC)
GOOD_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=63072000", "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


class _Stream:
    """`client.stream(...)` の戻り値（コンテキストマネージャー）の偽物。読んだバイト数を数える。"""

    def __init__(self, status, content_type, body, chunk=1000):
        self.status_code = status
        self.headers = httpx.Headers({"content-type": content_type})
        self._body = body.encode() if isinstance(body, str) else body
        self._chunk = chunk
        self.bytes_read = 0
        self.iterated = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def iter_bytes(self):
        self.iterated = True
        for i in range(0, len(self._body), self._chunk):
            part = self._body[i:i + self._chunk]
            self.bytes_read += len(part)
            yield part


def _stream_client(routes):
    """パスの末尾で応答を返す、偽のクライアント（`stream` だけを持つ。`get` は、使わない契約）。"""
    streams = []

    def stream(method, url, params=None):
        for suffix, (status, ctype, body) in routes.items():
            if url.endswith(suffix):
                streams.append(_Stream(status, ctype, body))
                return streams[-1]
        streams.append(_Stream(404, "", ""))
        return streams[-1]

    client = MagicMock()
    client.stream.side_effect = stream
    client.get.side_effect = AssertionError("client.get は、本文を全部読むため、使わない")
    client.streams = streams
    return client


def _rules(findings):
    return [f["rule"] for f in findings]


class TestSsrfGuard:
    def test_only_https_hostnames_resolving_to_public_addresses_are_safe(self):
        with patch.object(probes, "resolve_host", return_value=["93.184.216.34"]):
            assert probes.is_safe_target("https://example.com") is True
            assert probes.is_safe_target("http://example.com") is False     # https 以外
            assert probes.is_safe_target("https://") is False
            assert probes.is_safe_target("https://127.0.0.1") is False       # IP の直接指定
            assert probes.is_safe_target("https://[::1]/") is False

    def test_internal_resolution_is_rejected(self):
        for address in ("10.0.0.5", "127.0.0.1", "169.254.169.254", "192.168.1.1", "0.0.0.0", "::1", "fe80::1"):
            with patch.object(probes, "resolve_host", return_value=[address]):
                assert probes.is_safe_target("https://internal.example") is False, address

    def test_one_internal_address_among_public_ones_is_rejected(self):
        with patch.object(probes, "resolve_host", return_value=["93.184.216.34", "10.0.0.1"]):
            assert probes.is_safe_target("https://mixed.example") is False

    def test_unresolvable_hosts_are_not_safe_targets(self):
        with patch.object(probes, "resolve_host", return_value=None):
            assert probes.is_safe_target("https://gone.example") is False

    def test_resolve_host(self):
        infos = [(socket.AF_INET, 0, 0, "", ("1.2.3.4", 443)), (socket.AF_INET, 0, 0, "", ("1.2.3.4", 443))]
        with patch("socket.getaddrinfo", return_value=infos):
            assert probes.resolve_host("a.example") == ["1.2.3.4"]
        with patch("socket.getaddrinfo", side_effect=socket.gaierror):
            assert probes.resolve_host("a.example") is None


class TestTls:
    def test_thresholds(self):
        assert probes.evaluate_tls(60) == []
        assert probes.evaluate_tls(30)[0]["severity"] == "WARNING"
        assert probes.evaluate_tls(7)[0]["severity"] == "ERROR"
        assert probes.evaluate_tls(0)[0]["rule"] == "tls-expiring"
        expired = probes.evaluate_tls(-3)[0]
        assert (expired["rule"], expired["severity"]) == ("tls-expired", "ERROR") and "3日前" in expired["message"]

    def _connect(self, tls_object):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value = tls_object
        return patch("socket.create_connection", return_value=sock), patch("ssl.create_default_context", return_value=context)

    def test_reads_the_days_left_from_the_certificate(self):
        tls = MagicMock()
        tls.getpeercert.return_value = {"notAfter": "Jan  1 00:00:00 2030 GMT"}
        a, b = self._connect(tls)
        with a, b, patch("time.time", return_value=ssl.cert_time_to_seconds("Dec 22 00:00:00 2029 GMT")):
            days, findings = probes.check_tls("a.example")

        assert days == 10 and findings[0]["severity"] == "WARNING"

    def test_a_certificate_that_fails_verification_is_an_error(self):
        error = ssl.SSLCertVerificationError(1, "certificate has expired")
        error.verify_message = "certificate has expired"
        with patch("socket.create_connection", side_effect=error):
            days, findings = probes.check_tls("a.example")

        assert days is None and _rules(findings) == ["tls-invalid"]

    def test_connection_failures_are_warnings(self):
        with patch("socket.create_connection", side_effect=OSError("refused")):
            days, findings = probes.check_tls("a.example")
        assert days is None and _rules(findings) == ["tls-unreachable"]


class TestHeaders:
    def test_a_fully_hardened_response_has_no_findings(self):
        assert probes.evaluate_headers(GOOD_HEADERS) == []

    def test_missing_headers_are_reported_by_severity(self):
        findings = probes.evaluate_headers({})
        severities = {f["rule"]: f["severity"] for f in findings}

        assert severities == {
            "missing-csp": "WARNING", "missing-hsts": "WARNING", "missing-nosniff": "INFO",
            "missing-frame-protection": "INFO", "missing-referrer-policy": "INFO",
        }

    def test_header_names_are_case_insensitive_and_frame_ancestors_counts(self):
        headers = {k.lower(): v for k, v in GOOD_HEADERS.items()}
        assert probes.evaluate_headers(headers) == []
        no_csp_frame = {**GOOD_HEADERS, "Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY"}
        assert probes.evaluate_headers(no_csp_frame) == []


class TestExposure:
    def test_real_files_are_recognised_and_spa_fallbacks_are_not(self):
        html = "<!doctype html><html><body>app</body></html>"
        assert probes.looks_like_exposure("exposed-env", "text/plain", "DB_PASSWORD=x\nAPI_KEY=y\n") is True
        assert probes.looks_like_exposure("exposed-env", "text/html", html) is False
        assert probes.looks_like_exposure("exposed-env", "text/plain", "just some words") is False
        assert probes.looks_like_exposure("exposed-env", "text/plain", "") is False
        assert probes.looks_like_exposure("exposed-git", "text/plain", "ref: refs/heads/main") is True
        assert probes.looks_like_exposure("exposed-git", "text/plain", "[core]\n\trepositoryformatversion = 0") is True
        assert probes.looks_like_exposure("exposed-git", "text/html", html) is False
        assert probes.looks_like_exposure("exposed-firebase-json", "application/json", '{"hosting": {}}') is True
        assert probes.looks_like_exposure("exposed-firebase-json", "text/html", html) is False
        assert probes.looks_like_exposure("exposed-backup", "application/zip", "PK") is True
        assert probes.looks_like_exposure("exposed-backup", "text/html", html) is False
        assert probes.looks_like_exposure("unknown-rule", "text/plain", "x") is False

    def _client(self, routes):
        return _stream_client(routes)

    def test_exposed_files_are_errors_and_content_is_never_recorded(self):
        client = self._client({"/.env": (200, "text/plain", "SECRET_KEY=hunter2\n"),
                               "/.git/HEAD": (200, "text/plain", "ref: refs/heads/main")})

        findings = probes.probe_exposure(client, "https://a.example")

        assert _rules(findings) == ["exposed-env", "exposed-git"]
        assert all(f["severity"] == "ERROR" for f in findings)
        assert "hunter2" not in repr(findings)

    def test_a_spa_that_answers_200_for_everything_is_not_flagged(self):
        spa = (200, "text/html", "<!doctype html><html></html>")
        client = self._client({"/.env": spa, "/.git/HEAD": spa, "/.git/config": spa, "/firebase.json": spa, "/backup.zip": spa})
        assert probes.probe_exposure(client, "https://a.example") == []

    def test_network_errors_are_skipped_and_each_rule_is_reported_once(self):
        client = MagicMock()
        client.stream.side_effect = httpx.ConnectError("x")
        assert probes.probe_exposure(client, "https://a.example") == []

        both = self._client({"/.git/HEAD": (200, "text/plain", "ref: x"), "/.git/config": (200, "text/plain", "[core]")})
        assert _rules(probes.probe_exposure(both, "https://a.example")) == ["exposed-git"]


class TestResponseLimits:
    def test_the_body_is_cut_at_the_limit_and_reading_stops_early(self):
        client = _stream_client({"/": (200, "text/html", "a" * 1_000_000)})

        status, headers, text = probes.fetch_limited(client, "https://a.example/")

        assert status == 200 and len(text) == probes._MAX_BODY_BYTES
        # 100万バイトを、すべて読まない（上限に達したら打ち切る）
        assert client.streams[0].bytes_read < 100_000

    def test_the_body_can_be_skipped_entirely(self):
        client = _stream_client({"/": (200, "application/zip", "x" * 5000)})

        status, headers, text = probes.fetch_limited(client, "https://a.example/", read_body=False)

        assert (status, text) == (200, "") and headers["content-type"] == "application/zip"
        assert client.streams[0].iterated is False

    def test_undecodable_bytes_do_not_raise(self):
        client = _stream_client({"/": (200, "text/plain", b"\xff\xfe ok")})
        assert "ok" in probes.fetch_limited(client, "https://a.example/")[2]

    def test_a_backup_file_is_judged_by_its_type_without_reading_it(self):
        client = _stream_client({"/backup.zip": (200, "application/zip", "PK" * 10_000_000)})

        findings = probes.probe_exposure(client, "https://a.example")

        assert _rules(findings) == ["exposed-backup"]
        assert all(s.iterated is False for s in client.streams if s.headers.get("content-type") == "application/zip")

    def test_the_time_budget_stops_further_probes(self):
        client = _stream_client({})
        findings = probes.probe_exposure(client, "https://a.example", deadline=0.0)   # すでに超過
        assert findings == [] and client.streams == []


class TestDnsAndFirestore:
    def test_unresolvable_names_are_dangling(self):
        findings = probes.evaluate_takeover("old.example.com", None, None, "")
        assert _rules(findings) == ["dangling-dns"] and findings[0]["severity"] == "ERROR"

    def test_takeover_fingerprints(self):
        body = "<h1>There isn't a GitHub Pages site here.</h1>"
        assert _rules(probes.evaluate_takeover("a.example", ["1.2.3.4"], 404, body)) == ["subdomain-takeover"]
        assert probes.evaluate_takeover("a.example", ["1.2.3.4"], 200, "welcome") == []
        assert probes.evaluate_takeover("a.example", ["1.2.3.4"], 500, body) == []

    def test_firestore_readable_without_authentication_is_flagged(self):
        open_client = _stream_client({"/documents": (200, "application/json", "{}")})
        findings = probes.probe_firestore(open_client, "my-proj")
        assert _rules(findings) == ["firestore-public-read"] and "my-proj" in findings[0]["message"]
        assert open_client.streams[0].iterated is False     # 本文は、読まない

        closed = _stream_client({"/documents": (403, "application/json", "{}")})
        assert probes.probe_firestore(closed, "my-proj") == []
        broken = MagicMock()
        broken.stream.side_effect = httpx.ConnectError("x")
        assert probes.probe_firestore(broken, "my-proj") == []


class TestProbeSite:
    def _client_patch(self, response=None, error=None):
        client = MagicMock()
        client.__enter__.return_value = client
        if error:
            client.stream.side_effect = error
        else:
            client.stream.return_value = response
        return patch("httpx.Client", return_value=client)

    def test_combines_tls_headers_and_exposure(self):
        response = _Stream(200, "text/html", "<html>")
        with patch.object(probes, "resolve_host", return_value=["93.184.216.34"]), \
             patch.object(probes, "check_tls", return_value=(100, [])), \
             patch.object(probes, "probe_exposure", return_value=[probes._finding("exposed-env", "ERROR", "x")]), \
             patch.object(probes, "probe_firestore", return_value=[]) as firestore, \
             self._client_patch(response):
            days, findings = probes.probe_site("https://a.example:8443", "proj")

        assert days == 100
        assert "exposed-env" in _rules(findings) and "missing-csp" in _rules(findings)
        firestore.assert_called_once()

    def test_an_unresolvable_host_is_dangling_and_skips_the_network(self):
        with patch.object(probes, "resolve_host", return_value=None), patch.object(probes, "check_tls") as tls:
            days, findings = probes.probe_site("https://gone.example")

        assert days is None and _rules(findings) == ["dangling-dns"]
        tls.assert_not_called()

    def test_connection_errors_are_reported_as_unreachable(self):
        with patch.object(probes, "resolve_host", return_value=["93.184.216.34"]), \
             patch.object(probes, "check_tls", return_value=(100, [])), \
             patch.object(probes, "probe_exposure", return_value=[]), \
             self._client_patch(error=httpx.ConnectError("refused")):
            _, findings = probes.probe_site("https://a.example")

        assert "unreachable" in _rules(findings)


class TestTargets:
    def test_normalize_url(self):
        assert targets.normalize_url("https://a.example/path?x=1") == "https://a.example"
        assert targets.normalize_url("https://a.example:8443/x") == "https://a.example:8443"
        assert targets.normalize_url("http://a.example") is None
        assert targets.normalize_url("not a url") is None

    def test_firebase_project_id(self):
        assert targets.firebase_project_id('{"projects": {"default": "my-proj"}}') == "my-proj"
        assert targets.firebase_project_id('{"projects": {"prod": "p2"}}') == "p2"
        assert targets.firebase_project_id('{"projects": {}}') is None
        assert targets.firebase_project_id("not json") is None
        assert targets.firebase_project_id("[]") is None

    def test_discovers_homepage_pages_firebase_and_configured_urls_without_duplicates(self):
        repos = [
            {"full_name": "u/web", "homepage": "https://web.example/app", "has_pages": False},
            {"full_name": "u/u.github.io", "homepage": "", "has_pages": True},
            {"full_name": "u/app", "homepage": "https://web.example"},          # 重複
        ]

        def firebaserc(self, path):
            if self.full_name != "u/app":
                raise httpx.HTTPError("404")
            return '{"projects": {"default": "app-proj"}}'

        with patch("app.external_monitor.targets.GitHubRepo.file_content", firebaserc), \
             patch("app.external_monitor.targets.settings.EXTERNAL_MONITOR_URLS", "https://extra.example, http://insecure.example"):
            found = targets.discover_targets(repos, "tok")

        by_url = {t.url: t for t in found}
        assert set(by_url) == {"https://web.example", "https://u.github.io", "https://app-proj.web.app", "https://extra.example"}
        assert by_url["https://web.example"].source == "homepage" and by_url["https://web.example"].repo_full_name == "u/web"
        assert by_url["https://u.github.io"].source == "github_pages"
        assert by_url["https://app-proj.web.app"].firebase_project == "app-proj"
        assert by_url["https://extra.example"].repo_full_name is None


class TestJob:
    TARGET = Target("https://a.example", "homepage", "u/app")

    def _check(self, db, findings, days=100):
        with patch.object(probes, "is_safe_target", return_value=True), \
             patch.object(probes, "probe_site", return_value=(days, findings)):
            return check_target(db, self.TARGET)

    def test_unsafe_targets_are_never_probed(self, db_session):
        with patch.object(probes, "is_safe_target", return_value=False), \
             patch.object(probes, "probe_site") as probe:
            assert check_target(db_session, self.TARGET) == []

        probe.assert_not_called()
        assert db_session.query(SiteCheck).count() == 0

    def test_first_check_stores_results_without_alerting_on_existing_problems(self, db_session):
        worsened = self._check(db_session, [probes._finding("missing-csp", "WARNING", "m")])

        assert worsened == []
        row = db_session.query(SiteCheck).one()
        assert (row.tls_days_left, row.repo_full_name, row.source) == (100, "u/app", "homepage")

    def test_only_new_errors_and_warnings_are_reported_as_worsened(self, db_session):
        self._check(db_session, [probes._finding("missing-csp", "WARNING", "m")])

        worsened = self._check(db_session, [
            probes._finding("missing-csp", "WARNING", "m"),         # 既知
            probes._finding("exposed-env", "ERROR", "leak"),        # 新規
            probes._finding("missing-nosniff", "INFO", "i"),        # INFO は通知しない
        ])

        assert [(w["rule"], w["url"]) for w in worsened] == [("exposed-env", "https://a.example")]
        assert db_session.query(SiteCheck).count() == 1

    def test_job_counts_sites_issues_and_worsened_and_survives_a_failing_site(self, db_session):
        job = _SiteMonitorJob()
        counters = MagicMock(inserted=0, deleted=0, updated=0)
        sites = [Target("https://a.example", "homepage", "u/a"), Target("https://b.example", "config")]
        with patch("app.external_monitor.crawler.list_target_repos", return_value=[]), \
             patch("app.external_monitor.crawler.discover_targets", return_value=sites), \
             patch("app.external_monitor.crawler.check_target",
                   side_effect=[RuntimeError("boom"), [{"rule": "x", "severity": "ERROR", "message": "m", "url": "u"}]]):
            job.execute(db_session, counters)

        assert counters.inserted == 1 and counters.deleted == 1
        with patch("app.external_monitor.crawler.SiteAlertNotifier") as notifier:
            job.after_success(MagicMock(inserted=1, updated=0, deleted=1))
        assert notifier.call_args.args[0] == job.worsened
        with patch("app.external_monitor.crawler.SiteAlertNotifier", side_effect=RuntimeError("x")):
            job.after_success(MagicMock(inserted=1, updated=0, deleted=1))  # 例外を送出しない

    def test_result_and_entry_point(self):
        assert _SiteMonitorJob().result(MagicMock(inserted=3, deleted=2, updated=1)) == (3, 2, 1)
        from app.external_monitor.crawler import fetch_and_monitor_sites
        with patch("app.external_monitor.crawler._SiteMonitorJob") as cls:
            cls.return_value.run.return_value = (0, 0, 0)
            assert fetch_and_monitor_sites(force=True) == (0, 0, 0)

    def test_job_counts_sites_that_still_have_problems(self, db_session):
        db_session.add(SiteCheck(url="https://x.example", source="config", repo_full_name=None, tls_days_left=1,
                                 findings=[{"rule": "tls-expiring", "severity": "ERROR", "message": "m"}], checked_at=NOW))
        db_session.commit()
        job = _SiteMonitorJob()
        counters = MagicMock(inserted=0, deleted=0, updated=0)
        with patch("app.external_monitor.crawler.list_target_repos", return_value=[]), \
             patch("app.external_monitor.crawler.discover_targets", return_value=[]):
            job.execute(db_session, counters)
        assert counters.updated == 1


class TestApi:
    def _seed(self, db_session):
        db_session.add_all([
            SiteCheck(url="https://ok.example", source="homepage", repo_full_name="alice/ok", tls_days_left=90, findings=[], checked_at=NOW),
            SiteCheck(url="https://bad.example", source="homepage", repo_full_name="alice/bad", tls_days_left=3,
                      findings=[{"rule": "tls-expiring", "severity": "ERROR", "message": "m"}, {"rule": "i", "severity": "INFO", "message": "i"}], checked_at=NOW),
            SiteCheck(url="https://warn.example", source="config", repo_full_name=None, tls_days_left=20,
                      findings=[{"rule": "w", "severity": "WARNING", "message": "w"}], checked_at=NOW),
            SiteCheck(url="https://bob.example", source="homepage", repo_full_name="bob/app", tls_days_left=50, findings=[], checked_at=NOW),
        ])
        db_session.commit()

    def test_requires_authentication(self, client):
        assert client.get("/api/site-monitor").status_code in (401, 403)

    def test_lists_the_worst_sites_first_with_issue_counts(self, client, db_session):
        self._seed(db_session)

        body = client.get("/api/site-monitor", headers=HEADERS).json()

        assert [s["url"] for s in body["data"]] == ["https://bad.example", "https://warn.example", "https://bob.example", "https://ok.example"]
        assert (body["total"], body["sites_with_issues"]) == (4, 2)
        assert body["data"][0]["issues"] == 1          # INFO は、問題の数に含めない
        assert body["data"][0]["tls_days_left"] == 3

    def test_only_issues(self, client, db_session):
        self._seed(db_session)
        body = client.get("/api/site-monitor?only_issues=true", headers=HEADERS).json()
        assert [s["url"] for s in body["data"]] == ["https://bad.example", "https://warn.example"]

    def test_session_user_sees_only_sites_of_own_repositories(self, client, db_session):
        self._seed(db_session)
        token = create_session_token("alice")
        body = client.get("/api/site-monitor", headers={"Authorization": f"Bearer {token}"}).json()
        assert {s["url"] for s in body["data"]} == {"https://ok.example", "https://bad.example"}

    def test_manual_run_needs_the_admin_key(self, client):
        assert client.post("/admin/site-monitor-crawl").status_code in (401, 403)
        with patch("app.external_monitor.router.run_in_background") as run:
            res = client.post("/admin/site-monitor-crawl?force=true", headers=HEADERS)
        assert res.status_code == 202 and run.call_args[0][0] == "EXTMON"


class TestNotifier:
    FINDINGS = [
        {"url": "https://a.example", "rule": "w", "severity": "WARNING", "message": "ヘッダーがありません"},
        {"url": "https://b.example", "rule": "e", "severity": "ERROR", "message": "`/.env` が取得できます"},
    ]

    def test_has_content_only_with_findings(self):
        assert SiteAlertNotifier([]).has_content() is False
        assert SiteAlertNotifier(self.FINDINGS).has_content() is True

    def test_errors_come_first(self):
        message = SiteAlertNotifier(self.FINDINGS, recipients=["h"]).build_message()
        assert message.index("b.example") < message.index("a.example")
        assert ":rotating_light:" in message and ":warning:" in message

    def test_external_text_cannot_inject_slack_markup(self):
        evil = [{"url": "https://x.example/`<!channel>", "rule": "e", "severity": "ERROR", "message": "<https://evil|click> &\nfake"}]
        message = SiteAlertNotifier(evil, recipients=["h"]).build_message()

        assert "<!channel>" not in message and "<https://evil" not in message
        assert "&lt;!channel&gt;" in message

    def test_long_lists_are_cut_and_the_admin_is_the_only_default_recipient(self):
        many = [{"url": f"https://{i}.example", "rule": "e", "severity": "ERROR", "message": "m"} for i in range(20)]
        assert "ほか 5件" in SiteAlertNotifier(many, recipients=["h"]).build_message()
        with patch("app.core.notifications.recipients.resolve_admin_recipient", return_value=["h"]) as admin:
            assert SiteAlertNotifier([]).default_recipients() == ["h"]
        admin.assert_called_once()
