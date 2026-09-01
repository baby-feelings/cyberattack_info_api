"""依存ライブラリ脆弱性スキャン（DEPSCAN）機能のテスト。

GET /api/depscan・/api/depscan/stats・POST /admin/depscan-crawl のテストに加え、
GitHub API クライアント・クローラーロジック・Slack通知のユニットテストを含む。
外部 HTTP 通信（GitHub API・OSV API）はすべてモックする。
"""
import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

import httpx  # noqa: E402

from app.core.notifications import notify_dependency_findings  # noqa: E402
from app.depscan.crawler import (  # noqa: E402
    _build_findings,
    _collect_dependencies,
    _discover_manifests,
    _resolve_stale_findings,
    _upsert_findings,
    fetch_and_scan_dependencies,
)
from app.depscan.github_client import (  # noqa: E402
    get_file_content,
    get_repo_tree,
    list_target_repos,
)
from app.depscan.models import DependencyFinding  # noqa: E402

TEST_API_KEY = "test-api-key-for-pytest"
HEADERS = {"X-API-KEY": TEST_API_KEY}

_NOW = datetime.now(timezone.utc)


def _make_finding(db_session, **kwargs) -> DependencyFinding:
    defaults = {
        "repo_full_name": "baby-feelings/baby_grow",
        "ecosystem": "PyPI",
        "package_name": "cryptography",
        "installed_version": "3.4.7",
        "osv_id": "GHSA-test-0001",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "summary": "Test vulnerability",
        "fixed_versions": ["3.4.8"],
        "manifest_path": "requirements.txt",
        "detected_at": _NOW,
        "resolved_at": None,
    }
    defaults.update(kwargs)
    record = DependencyFinding(**defaults)
    db_session.add(record)
    db_session.commit()
    return record


def _mock_httpx_client(get_return=None, post_return=None) -> MagicMock:
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    if get_return is not None:
        mock_client.get = MagicMock(return_value=get_return)
    if post_return is not None:
        mock_client.post = MagicMock(return_value=post_return)
    return mock_client


def _mock_response(json_data) -> MagicMock:
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = json_data
    return resp


# ──────────────────────────────────────────────────────────────
# GET /api/depscan
# ──────────────────────────────────────────────────────────────


class TestListDepscan:
    def test_empty(self, client):
        res = client.get("/api/depscan", headers=HEADERS)
        assert res.status_code == 200
        assert res.json()["total"] == 0

    def test_requires_auth(self, client):
        res = client.get("/api/depscan")
        assert res.status_code == 403

    def test_returns_record(self, client, db_session):
        _make_finding(db_session)
        res = client.get("/api/depscan", headers=HEADERS)
        body = res.json()
        assert body["total"] == 1
        assert body["data"][0]["package_name"] == "cryptography"
        assert body["data"][0]["resolved_at"] is None

    def test_filter_by_repo(self, client, db_session):
        _make_finding(db_session, repo_full_name="baby-feelings/repo-a", osv_id="GHSA-a")
        _make_finding(db_session, repo_full_name="baby-feelings/repo-b", osv_id="GHSA-b")
        res = client.get("/api/depscan?repo=baby-feelings/repo-a", headers=HEADERS)
        body = res.json()
        assert body["total"] == 1
        assert body["data"][0]["repo_full_name"] == "baby-feelings/repo-a"

    def test_filter_by_ecosystem(self, client, db_session):
        _make_finding(db_session, ecosystem="PyPI", osv_id="GHSA-py")
        _make_finding(db_session, ecosystem="npm", package_name="axios", osv_id="GHSA-npm")
        res = client.get("/api/depscan?ecosystem=npm", headers=HEADERS)
        body = res.json()
        assert body["total"] == 1
        assert body["data"][0]["ecosystem"] == "npm"

    def test_filter_by_severity_case_insensitive(self, client, db_session):
        _make_finding(db_session, severity="CRITICAL", osv_id="GHSA-crit")
        res = client.get("/api/depscan?severity=critical", headers=HEADERS)
        assert res.json()["total"] == 1

    def test_filter_by_resolved(self, client, db_session):
        _make_finding(db_session, osv_id="GHSA-open")
        _make_finding(db_session, osv_id="GHSA-resolved", resolved_at=_NOW)
        res_open = client.get("/api/depscan?resolved=false", headers=HEADERS)
        res_resolved = client.get("/api/depscan?resolved=true", headers=HEADERS)
        assert res_open.json()["total"] == 1
        assert res_resolved.json()["total"] == 1
        assert res_resolved.json()["data"][0]["osv_id"] == "GHSA-resolved"

    def test_pagination(self, client, db_session):
        for i in range(3):
            _make_finding(db_session, osv_id=f"GHSA-{i}")
        res = client.get("/api/depscan?per_page=2&page=1", headers=HEADERS)
        assert len(res.json()["data"]) == 2


class TestDepscanStats:
    def test_empty(self, client):
        res = client.get("/api/depscan/stats", headers=HEADERS)
        assert res.status_code == 200
        assert res.json()["total"] == 0

    def test_requires_auth(self, client):
        res = client.get("/api/depscan/stats")
        assert res.status_code == 403

    def test_counts_unresolved_only(self, client, db_session):
        _make_finding(db_session, repo_full_name="baby-feelings/repo-a", osv_id="GHSA-open")
        _make_finding(
            db_session, repo_full_name="baby-feelings/repo-a",
            osv_id="GHSA-resolved", resolved_at=_NOW,
        )
        res = client.get("/api/depscan/stats", headers=HEADERS)
        body = res.json()
        assert body["total"] == 1
        assert body["repos"] == [{"repo_full_name": "baby-feelings/repo-a", "count": 1}]


# ──────────────────────────────────────────────────────────────
# POST /admin/depscan-crawl
# ──────────────────────────────────────────────────────────────


class TestAdminDepscanCrawl:
    def test_trigger_depscan_crawl(self, client):
        with patch("app.main.fetch_and_scan_dependencies", return_value=(0, 0, 0)):
            res = client.post("/admin/depscan-crawl", headers=HEADERS)
        assert res.status_code == 202
        assert "background" in res.json()["message"].lower()

    def test_requires_auth(self, client):
        res = client.post("/admin/depscan-crawl")
        assert res.status_code == 403


# ──────────────────────────────────────────────────────────────
# app.depscan.github_client
# ──────────────────────────────────────────────────────────────


class TestListTargetRepos:
    def test_excludes_fork_and_archived(self):
        repos = [
            {"full_name": "u/a", "fork": False, "archived": False},
            {"full_name": "u/fork", "fork": True, "archived": False},
            {"full_name": "u/old", "fork": False, "archived": True},
        ]
        mock_client = _mock_httpx_client(get_return=_mock_response(repos))
        with patch("app.depscan.github_client.httpx.Client", return_value=mock_client):
            result = list_target_repos("u", "token")
        assert [r["full_name"] for r in result] == ["u/a"]

    def test_paginates_until_short_page(self):
        page1 = [{"full_name": f"u/r{i}", "fork": False, "archived": False} for i in range(100)]
        page2 = [{"full_name": "u/last", "fork": False, "archived": False}]
        responses = [_mock_response(page1), _mock_response(page2)]
        mock_client = _mock_httpx_client()
        mock_client.get = MagicMock(side_effect=responses)
        with patch("app.depscan.github_client.httpx.Client", return_value=mock_client):
            result = list_target_repos("u", "token")
        assert len(result) == 101
        assert mock_client.get.call_count == 2


class TestGetRepoTree:
    def test_returns_blob_paths_only(self):
        tree_data = {
            "tree": [
                {"path": "requirements.txt", "type": "blob"},
                {"path": "app", "type": "tree"},
            ],
            "truncated": False,
        }
        mock_client = _mock_httpx_client(get_return=_mock_response(tree_data))
        with patch("app.depscan.github_client.httpx.Client", return_value=mock_client):
            paths = get_repo_tree("owner", "repo", "main", "token")
        assert paths == ["requirements.txt"]


class TestGetFileContent:
    def test_decodes_base64_content(self):
        import base64
        encoded = base64.b64encode(b"fastapi==0.115.6\n").decode()
        mock_client = _mock_httpx_client(
            get_return=_mock_response({"content": encoded, "encoding": "base64"})
        )
        with patch("app.depscan.github_client.httpx.Client", return_value=mock_client):
            content = get_file_content("owner", "repo", "requirements.txt", "token")
        assert content == "fastapi==0.115.6\n"

    def test_unsupported_encoding_raises(self):
        mock_client = _mock_httpx_client(
            get_return=_mock_response({"content": "x", "encoding": "utf-8"})
        )
        import pytest
        with patch("app.depscan.github_client.httpx.Client", return_value=mock_client):
            with pytest.raises(ValueError):
                get_file_content("owner", "repo", "path", "token")


# ──────────────────────────────────────────────────────────────
# app.depscan.crawler
# ──────────────────────────────────────────────────────────────


class TestDiscoverManifests:
    def test_filters_by_known_filenames(self):
        with patch(
            "app.depscan.crawler.get_repo_tree",
            return_value=["requirements.txt", "app/main.py", "dashboard/package-lock.json"],
        ):
            manifests = _discover_manifests("owner", "repo", "main", "token")
        assert manifests == ["requirements.txt", "dashboard/package-lock.json"]

    def test_http_error_returns_empty(self):
        with patch(
            "app.depscan.crawler.get_repo_tree",
            side_effect=httpx.HTTPStatusError("500", request=MagicMock(), response=MagicMock()),
        ):
            assert _discover_manifests("owner", "repo", "main", "token") == []


class TestCollectDependencies:
    def test_aggregates_across_repos(self):
        repos = [{"full_name": "u/repo1", "default_branch": "main"}]
        with patch("app.depscan.crawler.list_target_repos", return_value=repos), \
             patch("app.depscan.crawler._discover_manifests", return_value=["requirements.txt"]), \
             patch("app.depscan.crawler.get_file_content", return_value="fastapi==0.115.6\n"):
            dep_to_repos, repos_scanned = _collect_dependencies("u", "token")

        assert repos_scanned == 1
        assert dep_to_repos[("PyPI", "fastapi", "0.115.6")] == [("u/repo1", "requirements.txt")]

    def test_fetch_failure_skips_file(self):
        repos = [{"full_name": "u/repo1", "default_branch": "main"}]
        with patch("app.depscan.crawler.list_target_repos", return_value=repos), \
             patch("app.depscan.crawler._discover_manifests", return_value=["requirements.txt"]), \
             patch(
                 "app.depscan.crawler.get_file_content",
                 side_effect=httpx.HTTPStatusError(
                     "404", request=MagicMock(), response=MagicMock()
                 ),
             ):
            dep_to_repos, repos_scanned = _collect_dependencies("u", "token")
        assert dep_to_repos == {}
        assert repos_scanned == 1


class TestBuildFindings:
    def test_builds_records_from_hits(self):
        dep_to_repos = {("PyPI", "cryptography", "3.4.7"): [("u/repo1", "requirements.txt")]}
        vuln = {
            "id": "GHSA-crypto-001",
            "summary": "Vulnerable crypto",
            "affected": [
                {"ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.4.8"}]}]}
            ],
            "database_specific": {"severity": "HIGH"},
        }
        with patch(
            "app.depscan.crawler.query_versions_batch",
            return_value={("PyPI", "cryptography", "3.4.7"): ["GHSA-crypto-001"]},
        ), patch("app.depscan.crawler.fetch_vuln_by_id", return_value=vuln):
            records = _build_findings(dep_to_repos)

        assert len(records) == 1
        rec = records[0]
        assert rec["repo_full_name"] == "u/repo1"
        assert rec["osv_id"] == "GHSA-crypto-001"
        assert rec["severity"] == "HIGH"
        assert rec["fixed_versions"] == ["3.4.8"]

    def test_no_hits_returns_empty(self):
        with patch("app.depscan.crawler.query_versions_batch", return_value={}):
            assert _build_findings({("PyPI", "pkg", "1.0.0"): [("u/r", "requirements.txt")]}) == []

    def test_vuln_fetch_failure_skipped(self):
        dep_to_repos = {("PyPI", "pkg", "1.0.0"): [("u/r", "requirements.txt")]}
        with patch(
            "app.depscan.crawler.query_versions_batch",
            return_value={("PyPI", "pkg", "1.0.0"): ["GHSA-x"]},
        ), patch(
            "app.depscan.crawler.fetch_vuln_by_id",
            side_effect=httpx.HTTPStatusError("500", request=MagicMock(), response=MagicMock()),
        ):
            assert _build_findings(dep_to_repos) == []


class TestUpsertFindings:
    def _rec(self, **kwargs):
        base = {
            "repo_full_name": "baby-feelings/baby_grow",
            "ecosystem": "PyPI",
            "package_name": "cryptography",
            "installed_version": "3.4.7",
            "osv_id": "GHSA-001",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "summary": "vuln",
            "fixed_versions": ["3.4.8"],
            "manifest_path": "requirements.txt",
            "detected_at": _NOW,
        }
        base.update(kwargs)
        return base

    def test_inserts_new_finding(self, db_session):
        inserted, snapshots = _upsert_findings(db_session, [self._rec()])
        assert inserted == 1
        assert snapshots[0]["osv_id"] == "GHSA-001"
        assert db_session.query(DependencyFinding).count() == 1

    def test_dedupes_within_batch(self, db_session):
        inserted, _ = _upsert_findings(db_session, [self._rec(), self._rec()])
        assert inserted == 1

    def test_reopens_resolved_finding(self, db_session):
        _make_finding(db_session, osv_id="GHSA-001", resolved_at=_NOW)
        inserted, snapshots = _upsert_findings(db_session, [self._rec()])
        assert inserted == 0
        assert snapshots == []
        reopened = db_session.query(DependencyFinding).filter_by(osv_id="GHSA-001").first()
        assert reopened.resolved_at is None

    def test_existing_open_finding_not_reinserted(self, db_session):
        _make_finding(db_session, osv_id="GHSA-001")
        inserted, snapshots = _upsert_findings(db_session, [self._rec()])
        assert inserted == 0
        assert snapshots == []


class TestResolveStaleFindings:
    def test_marks_missing_findings_resolved(self, db_session):
        _make_finding(db_session, osv_id="GHSA-stale")
        resolved = _resolve_stale_findings(db_session, current_keys=set())
        assert resolved == 1
        finding = db_session.query(DependencyFinding).filter_by(osv_id="GHSA-stale").first()
        assert finding.resolved_at is not None

    def test_keeps_current_findings_open(self, db_session):
        _make_finding(db_session, osv_id="GHSA-current")
        key = ("baby-feelings/baby_grow", "PyPI", "cryptography", "GHSA-current")
        resolved = _resolve_stale_findings(db_session, current_keys={key})
        assert resolved == 0


class TestFetchAndScanDependencies:
    def test_success_path(self, db_session):
        with patch(
            "app.depscan.crawler._collect_dependencies",
            return_value=({("PyPI", "pkg", "1.0.0"): [("u/r", "requirements.txt")]}, 1),
        ), patch(
            "app.depscan.crawler._build_findings",
            return_value=[{
                "repo_full_name": "u/r", "ecosystem": "PyPI", "package_name": "pkg",
                "installed_version": "1.0.0", "osv_id": "GHSA-001", "severity": "HIGH",
                "cvss_score": 7.5, "summary": "vuln", "fixed_versions": [],
                "manifest_path": "requirements.txt", "detected_at": _NOW,
            }],
        ), patch("app.depscan.crawler.SessionLocal", return_value=db_session), \
           patch("app.depscan.crawler.notify_dependency_findings") as mock_notify:
            new_count, resolved_count, repos_scanned = fetch_and_scan_dependencies()

        assert new_count == 1
        assert repos_scanned == 1
        mock_notify.assert_called_once()

    def test_error_path_logs_and_notifies(self, db_session):
        with patch(
            "app.depscan.crawler._collect_dependencies",
            side_effect=RuntimeError("GitHub API down"),
        ), patch("app.depscan.crawler.SessionLocal", return_value=db_session), \
           patch("app.depscan.crawler.notify_depscan_crawl_error") as mock_notify_error:
            import pytest
            with pytest.raises(RuntimeError):
                fetch_and_scan_dependencies()
        mock_notify_error.assert_called_once()


# ──────────────────────────────────────────────────────────────
# app.core.notifications.notify_dependency_findings
# ──────────────────────────────────────────────────────────────


class TestNotifyDependencyFindings:
    def _finding_dict(self, **kwargs):
        base = {
            "repo_full_name": "baby-feelings/baby_grow",
            "package_name": "cryptography",
            "installed_version": "3.4.7",
            "severity": "HIGH",
            "fixed_versions": ["3.4.8"],
            "osv_id": "GHSA-001",
        }
        base.update(kwargs)
        return base

    def test_skips_when_no_webhook(self):
        with patch("app.core.notifications.settings.SLACK_WEBHOOK_URL", ""):
            with patch("app.core.notifications._send_slack") as mock_send:
                notify_dependency_findings([self._finding_dict()])
        mock_send.assert_not_called()

    def test_skips_when_empty(self):
        with patch("app.core.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/x"):
            with patch("app.core.notifications._send_slack") as mock_send:
                notify_dependency_findings([])
        mock_send.assert_not_called()

    def test_sends_digest_grouped_by_repo(self):
        findings = [
            self._finding_dict(repo_full_name="u/a", osv_id="GHSA-a"),
            self._finding_dict(repo_full_name="u/b", osv_id="GHSA-b"),
        ]
        with patch("app.core.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/x"):
            with patch("app.core.notifications._send_slack") as mock_send:
                notify_dependency_findings(findings)
        mock_send.assert_called_once()
        message = mock_send.call_args[0][0]
        assert "u/a" in message
        assert "u/b" in message
        assert "GHSA-a" in message
