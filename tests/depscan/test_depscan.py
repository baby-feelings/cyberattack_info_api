"""依存ライブラリ脆弱性スキャン（DEPSCAN）機能のテスト。

GET /api/depscan・/api/depscan/stats・POST /admin/depscan-crawl のテストに加え、
GitHub API クライアント・クローラーロジック・Slack通知のユニットテストを含む。
外部 HTTP 通信（GitHub API・OSV API）はすべてモックする。
"""
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

import httpx  # noqa: E402

from app.auth.session import create_session_token  # noqa: E402
from app.core.notifications import notify_dependency_findings  # noqa: E402
from app.depscan.crawler import (  # noqa: E402
    _build_findings,
    _collect_dependencies,
    _discover_manifests,
    _file_github_issues,
    _resolve_stale_findings,
    _upsert_findings,
    fetch_and_scan_dependencies,
)
from app.depscan.github_client import (  # noqa: E402
    add_issue_comment,
    create_issue,
    find_open_issue,
    get_file_content,
    get_repo_tree,
    list_target_repos,
)
from app.depscan.models import DependencyFinding, UserScan  # noqa: E402
from app.depscan.user_scan import (  # noqa: E402
    get_user_scan_status,
    run_depscan_for_user,
    should_rescan_for_user,
)

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

    def test_filter_by_owner(self, client, db_session):
        _make_finding(db_session, repo_full_name="baby-feelings/repo-a", osv_id="GHSA-a")
        _make_finding(db_session, repo_full_name="other-owner/repo-b", osv_id="GHSA-b")
        res = client.get("/api/depscan?owner=baby-feelings", headers=HEADERS)
        body = res.json()
        assert body["total"] == 1
        assert body["data"][0]["repo_full_name"] == "baby-feelings/repo-a"

    def test_filter_by_owner_does_not_match_substring(self, client, db_session):
        """`owner` はリポジトリオーナー単位の一致（前方一致 + '/'）で、部分文字列一致ではない。"""
        _make_finding(db_session, repo_full_name="baby-feelings-fork/repo-a", osv_id="GHSA-a")
        res = client.get("/api/depscan?owner=baby-feelings", headers=HEADERS)
        assert res.json()["total"] == 0

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

    def test_session_token_forces_owner_scope(self, client, db_session):
        """セッショントークン認証時、owner指定に関わらずログインユーザー本人のみに絞り込まれる。"""
        _make_finding(db_session, repo_full_name="octocat/repo-a", osv_id="GHSA-mine")
        _make_finding(db_session, repo_full_name="baby-feelings/baby_grow", osv_id="GHSA-others")
        with patch("app.depscan.router.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("octocat")
            res = client.get(
                "/api/depscan?owner=baby-feelings",
                headers={"Authorization": f"Bearer {token}"},
            )
        body = res.json()
        assert body["total"] == 1
        assert body["data"][0]["repo_full_name"] == "octocat/repo-a"

    def test_session_token_rejects_mismatched_repo_param(self, client, db_session):
        with patch("app.depscan.router.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("octocat")
            res = client.get(
                "/api/depscan?repo=baby-feelings/baby_grow",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert res.status_code == 403

    def test_invalid_session_token_and_no_api_key_returns_403(self, client):
        res = client.get(
            "/api/depscan", headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert res.status_code == 403


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

    def test_session_token_forces_owner_scope(self, client, db_session):
        _make_finding(db_session, repo_full_name="octocat/repo-a", osv_id="GHSA-mine")
        _make_finding(db_session, repo_full_name="baby-feelings/baby_grow", osv_id="GHSA-others")
        with patch("app.depscan.router.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("octocat")
            res = client.get(
                "/api/depscan/stats", headers={"Authorization": f"Bearer {token}"},
            )
        body = res.json()
        assert body["total"] == 1
        assert body["repos"] == [{"repo_full_name": "octocat/repo-a", "count": 1}]


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

    def test_uses_authenticated_user_repos_endpoint(self):
        """プライベートリポジトリも取得できるよう /user/repos (affiliation=owner) を使う。"""
        repos = [{"full_name": "u/private", "fork": False, "archived": False, "private": True}]
        mock_client = _mock_httpx_client(get_return=_mock_response(repos))
        with patch("app.depscan.github_client.httpx.Client", return_value=mock_client):
            list_target_repos("u", "token")
        call = mock_client.get.call_args
        assert call.args[0].endswith("/user/repos")
        assert call.kwargs["params"]["affiliation"] == "owner"


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


class TestFindOpenIssue:
    def test_returns_matching_issue_number(self):
        issues = [
            {"number": 5, "title": "別件のIssue"},
            {"number": 7, "title": "🚨 依存ライブラリの脆弱性が検出されました (DEPSCAN)"},
        ]
        mock_client = _mock_httpx_client(get_return=_mock_response(issues))
        with patch("app.depscan.github_client.httpx.Client", return_value=mock_client):
            result = find_open_issue(
                "owner", "repo", "🚨 依存ライブラリの脆弱性が検出されました (DEPSCAN)", "token",
            )
        assert result == 7

    def test_returns_none_when_not_found(self):
        mock_client = _mock_httpx_client(get_return=_mock_response([]))
        with patch("app.depscan.github_client.httpx.Client", return_value=mock_client):
            result = find_open_issue("owner", "repo", "存在しないタイトル", "token")
        assert result is None

    def test_ignores_pull_requests(self):
        """タイトルが一致してもPull Requestは除外する（issues APIはPRも含んで返すため）。"""
        issues = [{"number": 3, "title": "同じタイトル", "pull_request": {"url": "..."}}]
        mock_client = _mock_httpx_client(get_return=_mock_response(issues))
        with patch("app.depscan.github_client.httpx.Client", return_value=mock_client):
            result = find_open_issue("owner", "repo", "同じタイトル", "token")
        assert result is None


class TestCreateIssueAndComment:
    def test_create_issue_posts_title_and_body(self):
        mock_client = _mock_httpx_client(post_return=_mock_response({"number": 42}))
        with patch("app.depscan.github_client.httpx.Client", return_value=mock_client):
            result = create_issue("owner", "repo", "タイトル", "本文", "token")
        assert result == {"number": 42}
        call = mock_client.post.call_args
        assert call.kwargs["json"] == {"title": "タイトル", "body": "本文"}

    def test_add_issue_comment_posts_body(self):
        mock_client = _mock_httpx_client(post_return=_mock_response({"id": 1}))
        with patch("app.depscan.github_client.httpx.Client", return_value=mock_client):
            result = add_issue_comment("owner", "repo", 42, "追記内容", "token")
        assert result == {"id": 1}
        call = mock_client.post.call_args
        assert call.args[0].endswith("/issues/42/comments")
        assert call.kwargs["json"] == {"body": "追記内容"}


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

    def test_repo_owner_prefix_scopes_to_matching_repos_only(self, db_session):
        """repo_owner_prefix指定時、他オーナーの未解決findingには一切影響しない。"""
        _make_finding(
            db_session, repo_full_name="baby-feelings/baby_grow", osv_id="GHSA-baby-feelings",
        )
        _make_finding(db_session, repo_full_name="octocat/hello-world", osv_id="GHSA-octocat")

        resolved = _resolve_stale_findings(
            db_session, current_keys=set(), repo_owner_prefix="octocat",
        )

        assert resolved == 1
        baby_feelings_finding = (
            db_session.query(DependencyFinding).filter_by(osv_id="GHSA-baby-feelings").first()
        )
        octocat_finding = (
            db_session.query(DependencyFinding).filter_by(osv_id="GHSA-octocat").first()
        )
        assert baby_feelings_finding.resolved_at is None
        assert octocat_finding.resolved_at is not None


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
           patch("app.depscan.crawler.notify_dependency_findings") as mock_notify, \
           patch("app.depscan.crawler._file_github_issues") as mock_file_issues:
            new_count, resolved_count, repos_scanned = fetch_and_scan_dependencies()

        assert new_count == 1
        assert repos_scanned == 1
        mock_notify.assert_called_once()
        mock_file_issues.assert_called_once()

    def test_error_path_logs_and_notifies(self, db_session):
        with patch(
            "app.depscan.crawler._collect_dependencies",
            side_effect=RuntimeError("GitHub API down"),
        ), patch("app.depscan.crawler.SessionLocal", return_value=db_session), \
           patch("app.depscan.crawler.notify_error") as mock_notify_error:
            import pytest
            with pytest.raises(RuntimeError):
                fetch_and_scan_dependencies()
        mock_notify_error.assert_called_once()


class TestFileGithubIssues:
    def _finding(self, **kwargs):
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

    def test_does_nothing_when_no_new_findings(self):
        with patch("app.depscan.crawler.find_open_issue") as mock_find:
            _file_github_issues([])
        mock_find.assert_not_called()

    def test_creates_issue_when_none_open(self):
        with patch("app.depscan.crawler.find_open_issue", return_value=None), \
             patch("app.depscan.crawler.create_issue") as mock_create, \
             patch("app.depscan.crawler.add_issue_comment") as mock_comment:
            _file_github_issues([self._finding()])
        mock_create.assert_called_once()
        args = mock_create.call_args[0]
        assert args[0] == "baby-feelings"
        assert args[1] == "baby_grow"
        assert "cryptography" in args[3]
        mock_comment.assert_not_called()

    def test_comments_on_existing_open_issue(self):
        with patch("app.depscan.crawler.find_open_issue", return_value=7), \
             patch("app.depscan.crawler.create_issue") as mock_create, \
             patch("app.depscan.crawler.add_issue_comment") as mock_comment:
            _file_github_issues([self._finding()])
        mock_comment.assert_called_once()
        assert mock_comment.call_args[0][2] == 7
        mock_create.assert_not_called()

    def test_groups_by_repo(self):
        findings = [
            self._finding(repo_full_name="u/a", osv_id="GHSA-a"),
            self._finding(repo_full_name="u/b", osv_id="GHSA-b"),
        ]
        with patch("app.depscan.crawler.find_open_issue", return_value=None), \
             patch("app.depscan.crawler.create_issue") as mock_create, \
             patch("app.depscan.crawler.add_issue_comment"):
            _file_github_issues(findings)
        assert mock_create.call_count == 2

    def test_http_error_does_not_raise(self):
        """権限不足等でIssue作成が失敗しても、DEPSCAN全体を失敗させない。"""
        with patch(
            "app.depscan.crawler.find_open_issue",
            side_effect=httpx.HTTPStatusError("403", request=MagicMock(), response=MagicMock()),
        ):
            _file_github_issues([self._finding()])  # 例外を送出しないことを確認


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
        assert "cryptography" in message

    def test_consolidates_same_package_into_one_line(self):
        """同一パッケージ×バージョンの複数CVEは1行に集約され、件数・重大度内訳を表示する。"""
        findings = [
            self._finding_dict(osv_id="GHSA-a", severity="HIGH", fixed_versions=["3.4.8"]),
            self._finding_dict(osv_id="GHSA-b", severity="CRITICAL", fixed_versions=["3.5.0"]),
            self._finding_dict(osv_id="GHSA-c", severity="HIGH", fixed_versions=["3.4.8"]),
        ]
        with patch("app.core.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/x"):
            with patch("app.core.notifications._send_slack") as mock_send:
                notify_dependency_findings(findings)
        message = mock_send.call_args[0][0]
        # 3件のCVEが1行（1パッケージ）に集約されている
        assert message.count("cryptography 3.4.7") == 1
        assert "CRITICAL×1" in message
        assert "HIGH×2" in message
        assert "計3件" in message
        assert "3.4.8" in message and "3.5.0" in message

    def test_sorts_packages_by_severity_within_repo(self):
        """リポジトリ内はCRITICAL→HIGH→...の重大度順に並ぶ。"""
        findings = [
            self._finding_dict(package_name="low-pkg", severity="LOW", osv_id="GHSA-l"),
            self._finding_dict(package_name="critical-pkg", severity="CRITICAL", osv_id="GHSA-c"),
            self._finding_dict(package_name="high-pkg", severity="HIGH", osv_id="GHSA-h"),
        ]
        with patch("app.core.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/x"):
            with patch("app.core.notifications._send_slack") as mock_send:
                notify_dependency_findings(findings)
        message = mock_send.call_args[0][0]
        assert (
            message.index("critical-pkg")
            < message.index("high-pkg")
            < message.index("low-pkg")
        )

    def test_no_repo_limit(self):
        """対象リポジトリ数が多くても省略せず全リポジトリを表示する。"""
        findings = [
            self._finding_dict(repo_full_name=f"u/repo{i}", osv_id=f"GHSA-{i}")
            for i in range(20)
        ]
        with patch("app.core.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/x"):
            with patch("app.core.notifications._send_slack") as mock_send:
                notify_dependency_findings(findings)
        message = mock_send.call_args[0][0]
        for i in range(20):
            assert f"u/repo{i}" in message
        assert "他" not in message

    def test_truncates_overly_long_message(self):
        """Slack の文字数上限を超える場合、行の途中で切らずに省略する。"""
        findings = [
            self._finding_dict(
                repo_full_name=f"u/repo{i}", package_name=f"pkg-{i}", osv_id=f"GHSA-{i}",
            )
            for i in range(2000)
        ]
        with patch("app.core.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/x"):
            with patch("app.core.notifications._send_slack") as mock_send:
                notify_dependency_findings(findings)
        message = mock_send.call_args[0][0]
        assert len(message) <= 39000 + 100
        assert message.endswith(
            "（メッセージが長すぎるため以降省略。詳細は API / ダッシュボードを参照）"
        )
        assert not message.endswith("\n")


# ──────────────────────────────────────────────────────────────
# app.depscan.user_scan.run_depscan_for_user / get_user_scan_status
# ──────────────────────────────────────────────────────────────


class TestRunDepscanForUser:
    def test_success_path_records_done_status(self, db_session):
        with patch(
            "app.depscan.user_scan._collect_dependencies",
            return_value=({("PyPI", "pkg", "1.0.0"): [("octocat/repo", "requirements.txt")]}, 1),
        ), patch(
            "app.depscan.user_scan._build_findings",
            return_value=[{
                "repo_full_name": "octocat/repo", "ecosystem": "PyPI", "package_name": "pkg",
                "installed_version": "1.0.0", "osv_id": "GHSA-001", "severity": "HIGH",
                "cvss_score": 7.5, "summary": "vuln", "fixed_versions": [],
                "manifest_path": "requirements.txt", "detected_at": _NOW,
            }],
        ), patch("app.depscan.user_scan.SessionLocal", return_value=db_session):
            run_depscan_for_user("octocat", "gho_token")

        scan = db_session.query(UserScan).filter_by(username="octocat").first()
        assert scan.status == "done"
        assert scan.repos_scanned == 1
        assert scan.finished_at is not None
        findings_count = (
            db_session.query(DependencyFinding).filter_by(repo_full_name="octocat/repo").count()
        )
        assert findings_count == 1

    def test_does_not_resolve_other_owners_findings(self, db_session):
        """他オーナー（baby-feelings等）の未解決findingを誤って解決済みにしないこと。"""
        _make_finding(db_session, repo_full_name="baby-feelings/baby_grow", osv_id="GHSA-untouched")

        with patch(
            "app.depscan.user_scan._collect_dependencies", return_value=({}, 0),
        ), patch(
            "app.depscan.user_scan._build_findings", return_value=[],
        ), patch("app.depscan.user_scan.SessionLocal", return_value=db_session):
            run_depscan_for_user("octocat", "gho_token")

        untouched = db_session.query(DependencyFinding).filter_by(osv_id="GHSA-untouched").first()
        assert untouched.resolved_at is None

    def test_failure_records_error_status(self, db_session):
        with patch(
            "app.depscan.user_scan._collect_dependencies",
            side_effect=RuntimeError("GitHub API down"),
        ), patch("app.depscan.user_scan.SessionLocal", return_value=db_session):
            run_depscan_for_user("octocat", "gho_token")  # 例外を送出しないことを確認

        scan = db_session.query(UserScan).filter_by(username="octocat").first()
        assert scan.status == "error"
        assert "GitHub API down" in scan.error_message

    def test_second_run_updates_existing_status_row(self, db_session):
        with patch(
            "app.depscan.user_scan._collect_dependencies", return_value=({}, 0),
        ), patch(
            "app.depscan.user_scan._build_findings", return_value=[],
        ), patch("app.depscan.user_scan.SessionLocal", return_value=db_session):
            run_depscan_for_user("octocat", "gho_token")
            run_depscan_for_user("octocat", "gho_token")

        assert db_session.query(UserScan).filter_by(username="octocat").count() == 1


class TestGetUserScanStatus:
    def test_returns_none_when_never_scanned(self, db_session):
        assert get_user_scan_status(db_session, "nobody") is None

    def test_returns_recorded_scan(self, db_session):
        db_session.add(UserScan(
            username="octocat", status="done", repos_scanned=3,
            started_at=_NOW, finished_at=_NOW,
        ))
        db_session.commit()
        scan = get_user_scan_status(db_session, "octocat")
        assert scan is not None
        assert scan.status == "done"
        assert scan.repos_scanned == 3


class TestShouldRescanForUser:
    def test_no_scan_yet_returns_true(self, db_session):
        assert should_rescan_for_user(db_session, "octocat") is True

    def test_error_status_returns_true(self, db_session):
        db_session.add(UserScan(
            username="octocat", status="error", started_at=_NOW, finished_at=_NOW,
            error_message="boom",
        ))
        db_session.commit()
        assert should_rescan_for_user(db_session, "octocat") is True

    def test_running_status_returns_false(self, db_session):
        db_session.add(UserScan(username="octocat", status="running", started_at=_NOW))
        db_session.commit()
        assert should_rescan_for_user(db_session, "octocat") is False

    def test_recent_done_scan_returns_false(self, db_session):
        db_session.add(UserScan(
            username="octocat", status="done", started_at=_NOW, finished_at=_NOW,
        ))
        db_session.commit()
        assert should_rescan_for_user(db_session, "octocat") is False

    def test_stale_done_scan_returns_true(self, db_session):
        stale = _NOW - timedelta(hours=25)
        db_session.add(UserScan(
            username="octocat", status="done", started_at=stale, finished_at=stale,
        ))
        db_session.commit()
        assert should_rescan_for_user(db_session, "octocat") is True
