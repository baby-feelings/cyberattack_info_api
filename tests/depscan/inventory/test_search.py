"""app.depscan.inventory（検索・集計）と GET /api/depscan/dependencies（横断検索）のテスト。"""
import os
from datetime import UTC, datetime
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.auth.session import create_session_token  # noqa: E402
from app.depscan.inventory.filters import DependencyFilter  # noqa: E402
from app.depscan.inventory.search import search_dependencies, summarize_repos  # noqa: E402
from app.depscan.models import RepoDependency  # noqa: E402
from tests.depscan.support import make_finding  # noqa: E402


def _search(db, *, page=1, per_page=50, forced_owner=None, **conditions):
    """条件（package・version など）から `DependencyFilter` を作って、検索する。"""
    flt = DependencyFilter(owner=forced_owner, **conditions)
    return search_dependencies(db, flt, page=page, per_page=per_page)


def _summarize(db, *, forced_owner=None, **conditions):
    return summarize_repos(db, DependencyFilter(owner=forced_owner, **conditions))


HEADERS = {"X-API-KEY": "test-api-key-for-pytest"}
_URL = "/api/depscan/dependencies"


def _dep(db_session, repo, name, version="1.0.0", ecosystem="npm", path="package-lock.json"):
    db_session.add(RepoDependency(
        repo_full_name=repo, ecosystem=ecosystem, package_name=name, version=version,
        manifest_path=path,
    ))
    db_session.commit()


def _seed(db_session):
    _dep(db_session, "alice/web", "undici", "8.11.2")
    _dep(db_session, "alice/web", "axios", "1.6.0")
    _dep(db_session, "alice/api", "undici", "8.12.3")
    _dep(db_session, "alice/api", "fastapi", "0.141.0", ecosystem="PyPI", path="requirements.txt")
    _dep(db_session, "bob/app", "undici", "8.11.2")


class TestSearchDependencies:
    def test_returns_all_without_filters(self, db_session):
        _seed(db_session)
        total, rows = _search(db_session, page=1, per_page=50)
        assert total == 5
        assert len(rows) == 5

    def test_package_is_partial_and_case_insensitive(self, db_session):
        _seed(db_session)
        total, rows = _search(db_session, page=1, per_page=50, package="UNDI")
        assert total == 3
        assert {r.package_name for r, _ in rows} == {"undici"}

    def test_version_is_exact_match(self, db_session):
        _seed(db_session)
        total, rows = _search(
            db_session, page=1, per_page=50, package="undici", version="8.11.2",
        )
        assert total == 2
        assert {r.repo_full_name for r, _ in rows} == {"alice/web", "bob/app"}

    def test_ecosystem_and_repo_filters(self, db_session):
        _seed(db_session)
        _, rows = _search(db_session, page=1, per_page=50, ecosystem="PyPI")
        assert [r.package_name for r, _ in rows] == ["fastapi"]
        _, rows = _search(db_session, page=1, per_page=50, repo="alice/api")
        assert {r.package_name for r, _ in rows} == {"undici", "fastapi"}

    def test_like_wildcards_in_package_are_literal(self, db_session):
        """`%` `_` を含む検索語がワイルドカードとして働かず、全件にヒットしないこと。"""
        _seed(db_session)
        total, _ = _search(db_session, page=1, per_page=50, package="%")
        assert total == 0
        total, _ = _search(db_session, page=1, per_page=50, package="_")
        assert total == 0

    def test_forced_owner_limits_to_that_owner(self, db_session):
        _seed(db_session)
        total, rows = _search(
            db_session, page=1, per_page=50, package="undici", forced_owner="alice",
        )
        assert total == 2
        assert all(r.repo_full_name.startswith("alice/") for r, _ in rows)

    def test_forced_owner_does_not_match_a_longer_owner_name(self, db_session):
        """オーナー名の前方一致が「alice」で「alice2/...」にも当たらないこと（'/'まで含めて比較する）。"""
        _dep(db_session, "alice2/app", "undici")
        total, _ = _search(db_session, page=1, per_page=50, forced_owner="alice")
        assert total == 0

    def test_pagination_is_stable(self, db_session):
        _seed(db_session)
        _, first = _search(db_session, page=1, per_page=2)
        _, second = _search(db_session, page=2, per_page=2)
        _, third = _search(db_session, page=3, per_page=2)
        keys = [(r.repo_full_name, r.package_name, r.version) for r, _ in first + second + third]
        assert len(keys) == 5
        assert len(set(keys)) == 5

    def test_open_vulnerabilities_counts_only_unresolved_for_that_version(self, db_session):
        _seed(db_session)
        make_finding(
            db_session, repo_full_name="alice/web", ecosystem="npm", package_name="undici",
            installed_version="8.11.2", osv_id="GHSA-1",
        )
        make_finding(
            db_session, repo_full_name="alice/web", ecosystem="npm", package_name="undici",
            installed_version="8.11.2", osv_id="GHSA-2",
        )
        make_finding(  # 解決済みは数えない
            db_session, repo_full_name="alice/web", ecosystem="npm", package_name="undici",
            installed_version="8.11.2", osv_id="GHSA-3", resolved_at=datetime.now(UTC),
        )
        make_finding(  # 別の版・別のリポジトリの検知は混ざらない
            db_session, repo_full_name="alice/api", ecosystem="npm", package_name="undici",
            installed_version="8.11.2", osv_id="GHSA-4",
        )
        _, rows = _search(db_session, page=1, per_page=50, package="undici")
        counts = {(r.repo_full_name, r.version): n for r, n in rows}
        assert counts == {
            ("alice/web", "8.11.2"): 2,
            ("alice/api", "8.12.3"): 0,
            ("bob/app", "8.11.2"): 0,
        }

    def test_empty_result(self, db_session):
        assert _search(db_session, page=1, per_page=50, package="nothing") == (0, [])

    def test_vulnerable_only_returns_dependencies_with_open_findings(self, db_session):
        _seed(db_session)
        make_finding(
            db_session, repo_full_name="alice/web", ecosystem="npm", package_name="undici",
            installed_version="8.11.2",
        )
        make_finding(  # 解決済みの検知だけの依存は「脆弱性あり」に含めない
            db_session, repo_full_name="alice/web", ecosystem="npm", package_name="axios",
            installed_version="1.6.0", resolved_at=datetime.now(UTC),
        )
        total, rows = _search(db_session, page=1, per_page=50, vulnerable=True)
        assert total == 1
        assert [(r.repo_full_name, r.package_name) for r, _ in rows] == [("alice/web", "undici")]

    def test_operating_filter_uses_inactive_repos(self, db_session):
        _seed(db_session)
        with patch("app.core.operating_status.settings.INACTIVE_REPOS", "bob/app"):
            active, _ = _search(db_session, page=1, per_page=50, operating="active")
            inactive, rows = _search(
                db_session, page=1, per_page=50, operating="inactive",
            )
            everything, _ = _search(db_session, page=1, per_page=50, operating="all")
        assert (active, inactive, everything) == (4, 1, 5)
        assert rows[0][0].repo_full_name == "bob/app"


class TestSummarizeRepos:
    def test_counts_dependencies_and_vulnerable_ones_per_repo(self, db_session):
        _seed(db_session)
        make_finding(
            db_session, repo_full_name="alice/web", ecosystem="npm", package_name="undici",
            installed_version="8.11.2", osv_id="GHSA-1",
        )
        make_finding(  # 同じ依存への複数の検知は、依存1件として数える
            db_session, repo_full_name="alice/web", ecosystem="npm", package_name="undici",
            installed_version="8.11.2", osv_id="GHSA-2",
        )
        # 検知がある alice/web が先頭、あとはリポジトリ名順
        assert _summarize(db_session) == [
            ("alice/web", 2, 1), ("alice/api", 2, 0), ("bob/app", 1, 0),
        ]

    def test_forced_owner_and_operating(self, db_session):
        _seed(db_session)
        assert [r for r, _, _ in _summarize(db_session, forced_owner="alice")] == [
            "alice/api", "alice/web",
        ]
        with patch("app.core.operating_status.settings.INACTIVE_REPOS", "alice/api"):
            assert [r for r, _, _ in _summarize(db_session, operating="active")] == [
                "alice/web", "bob/app",
            ]

    def test_empty(self, db_session):
        assert _summarize(db_session) == []


class TestDependenciesEndpoint:
    def test_requires_auth(self, client):
        assert client.get(_URL).status_code == 403

    def test_search_returns_purl_and_open_vulnerabilities(self, client, db_session):
        _seed(db_session)
        make_finding(
            db_session, repo_full_name="alice/web", ecosystem="npm", package_name="undici",
            installed_version="8.11.2",
        )
        res = client.get(f"{_URL}?package=undici&version=8.11.2", headers=HEADERS)

        assert res.status_code == 200
        body = res.json()
        assert body["total"] == 2
        by_repo = {row["repo_full_name"]: row for row in body["data"]}
        assert by_repo["alice/web"]["purl"] == "pkg:npm/undici@8.11.2"
        assert by_repo["alice/web"]["open_vulnerabilities"] == 1
        assert by_repo["bob/app"]["open_vulnerabilities"] == 0
        assert by_repo["alice/web"]["manifest_path"] == "package-lock.json"

    def test_pagination_params(self, client, db_session):
        _seed(db_session)
        res = client.get(f"{_URL}?per_page=2&page=2", headers=HEADERS)
        body = res.json()
        assert (body["total"], body["page"], body["per_page"], len(body["data"])) == (5, 2, 2, 2)

    def test_invalid_per_page_is_rejected(self, client):
        assert client.get(f"{_URL}?per_page=1000", headers=HEADERS).status_code == 422

    def test_session_token_sees_only_own_repos(self, client, db_session):
        _seed(db_session)
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("alice")
            res = client.get(
                f"{_URL}?package=undici", headers={"Authorization": f"Bearer {token}"},
            )
        assert res.status_code == 200
        repos = {row["repo_full_name"] for row in res.json()["data"]}
        assert repos == {"alice/web", "alice/api"}

    def test_session_token_cannot_query_other_users_repo(self, client, db_session):
        _seed(db_session)
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("alice")
            res = client.get(
                f"{_URL}?repo=bob/app", headers={"Authorization": f"Bearer {token}"},
            )
        assert res.status_code == 200
        assert res.json()["data"] == []

    def test_vulnerable_filter(self, client, db_session):
        _seed(db_session)
        make_finding(
            db_session, repo_full_name="alice/web", ecosystem="npm", package_name="undici",
            installed_version="8.11.2",
        )
        res = client.get(f"{_URL}?vulnerable=true", headers=HEADERS)
        assert [row["package_name"] for row in res.json()["data"]] == ["undici"]

    def test_operating_filter(self, client, db_session):
        _seed(db_session)
        with patch("app.core.operating_status.settings.INACTIVE_REPOS", "bob/app"):
            res = client.get(f"{_URL}?operating=inactive", headers=HEADERS)
        assert [row["repo_full_name"] for row in res.json()["data"]] == ["bob/app"]

    def test_invalid_operating_is_rejected(self, client):
        assert client.get(f"{_URL}?operating=maybe", headers=HEADERS).status_code == 422


class TestDependencyReposEndpoint:
    def test_requires_auth(self, client):
        assert client.get(f"{_URL}/repos").status_code == 403

    def test_lists_repos_with_counts_most_vulnerable_first(self, client, db_session):
        _seed(db_session)
        make_finding(
            db_session, repo_full_name="alice/api", ecosystem="npm", package_name="undici",
            installed_version="8.12.3",
        )
        res = client.get(f"{_URL}/repos", headers=HEADERS)
        assert res.status_code == 200
        assert res.json()["repos"] == [
            {"repo_full_name": "alice/api", "total": 2, "vulnerable": 1},
            {"repo_full_name": "alice/web", "total": 2, "vulnerable": 0},
            {"repo_full_name": "bob/app", "total": 1, "vulnerable": 0},
        ]

    def test_session_token_sees_only_own_repos(self, client, db_session):
        _seed(db_session)
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("alice")
            res = client.get(f"{_URL}/repos", headers={"Authorization": f"Bearer {token}"})
        assert {r["repo_full_name"] for r in res.json()["repos"]} == {"alice/api", "alice/web"}

    def test_operating_filter(self, client, db_session):
        _seed(db_session)
        with patch("app.core.operating_status.settings.INACTIVE_REPOS", "bob/app"):
            res = client.get(f"{_URL}/repos?operating=active", headers=HEADERS)
        assert {r["repo_full_name"] for r in res.json()["repos"]} == {"alice/api", "alice/web"}
