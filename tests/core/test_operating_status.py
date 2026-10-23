"""運用状態（運用中／運用停止中）による絞り込みのテスト（INACTIVE_REPOS）。

DEPSCAN・CODESCAN・DEPSOPS の一覧・統計 API が、`operating=active|inactive|all` で、運用中と
運用停止中のリポジトリを分けて返すこと、未指定なら従来どおり全件であることを確認する。
"""
import os
from datetime import UTC, datetime
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")

import pytest  # noqa: E402

from app.codescan.models import CodeFinding  # noqa: E402
from app.core.operating_status import (  # noqa: E402
    apply_operating_status,
    inactive_repo_names,
    is_inactive_repo,
)
from app.depscan.models import DependencyFinding  # noqa: E402
from app.depsops.models import DependabotPrLog  # noqa: E402

_NOW = datetime.now(UTC)
_HEADERS = {"X-API-KEY": "test-api-key-for-pytest"}
_CFG = "app.core.operating_status.settings.INACTIVE_REPOS"
_ACTIVE = "baby-feelings/baby_compass"
_STOPPED = "baby-feelings/baby_grow"


def _code(db, repo, line=1):
    db.add(CodeFinding(
        repo_full_name=repo, file_path="a.py", line_start=line, line_end=line, rule_id="r",
        message="m", severity="ERROR", cwe_ids=[], owasp_categories=[], code_snippet="x",
        cvss_score=None, cvss_vector=None, detected_at=_NOW,
    ))


def _dep(db, repo):
    db.add(DependencyFinding(
        repo_full_name=repo, ecosystem="npm", package_name="p", installed_version="1.0.0",
        osv_id="GHSA-1", summary="s", fixed_versions=[], manifest_path="package.json",
        detected_at=_NOW,
    ))


def _pr(db, repo, number=1):
    db.add(DependabotPrLog(
        repo_full_name=repo, pr_number=number, title="Bump x", action="flagged", reason="r",
        processed_at=_NOW,
    ))


@pytest.fixture(autouse=True)
def _clean(db_session):
    yield
    for model in (CodeFinding, DependencyFinding, DependabotPrLog):
        db_session.query(model).delete()
    db_session.commit()


@pytest.fixture
def seeded(db_session):
    """運用中・運用停止中のリポジトリに、3ドメインの検知を1件ずつ入れる。"""
    for repo in (_ACTIVE, _STOPPED):
        _code(db_session, repo)
        _dep(db_session, repo)
        _pr(db_session, repo)
    db_session.commit()


class TestSettingHelpers:
    def test_parses_and_lowercases_the_list(self):
        with patch(_CFG, "Baby-Feelings/Baby_Grow, u/x ,,"):
            assert inactive_repo_names() == {"baby-feelings/baby_grow", "u/x"}

    def test_empty_means_nothing_is_inactive(self):
        with patch(_CFG, ""):
            assert inactive_repo_names() == set()
            assert is_inactive_repo(_STOPPED) is False

    def test_is_inactive_repo_ignores_case(self):
        with patch(_CFG, _STOPPED):
            assert is_inactive_repo("BABY-FEELINGS/Baby_Grow") is True
            assert is_inactive_repo(_ACTIVE) is False


class TestApplyOperatingStatus:
    def test_filters_by_status_case_insensitively(self, db_session, seeded):
        query = db_session.query(CodeFinding)
        with patch(_CFG, "Baby-Feelings/BABY_GROW"):
            active = apply_operating_status(query, CodeFinding.repo_full_name, "active").all()
            stopped = apply_operating_status(query, CodeFinding.repo_full_name, "inactive").all()
            everything = apply_operating_status(query, CodeFinding.repo_full_name, "all").all()

        assert [f.repo_full_name for f in active] == [_ACTIVE]
        assert [f.repo_full_name for f in stopped] == [_STOPPED]
        assert len(everything) == 2

    def test_everything_is_active_when_nothing_is_listed(self, db_session, seeded):
        with patch(_CFG, ""):
            query = apply_operating_status(
                db_session.query(CodeFinding), CodeFinding.repo_full_name, "active",
            )
            assert query.count() == 2


# (エンドポイント, レスポンスから「リポジトリ名の一覧」を取り出す関数)
def _list_repos(body):
    return sorted(item["repo_full_name"] for item in body["data"])


def _stat_repos(body):
    return sorted(item["repo_full_name"] for item in body["repos"])


_ENDPOINTS = [
    pytest.param("/api/codescan", _list_repos, id="codescan-list"),
    pytest.param("/api/codescan/stats", _stat_repos, id="codescan-stats"),
    pytest.param("/api/depscan", _list_repos, id="depscan-list"),
    pytest.param("/api/depscan/stats", _stat_repos, id="depscan-stats"),
    pytest.param("/api/depsops", _list_repos, id="depsops-list"),
    pytest.param("/api/depsops/stats", _stat_repos, id="depsops-stats"),
]


class TestEndpoints:
    @pytest.mark.parametrize(("path", "repos_of"), _ENDPOINTS)
    def test_active_returns_only_running_apps(self, client, seeded, path, repos_of):
        with patch(_CFG, _STOPPED):
            resp = client.get(path, params={"operating": "active"}, headers=_HEADERS)
        assert resp.status_code == 200
        assert repos_of(resp.json()) == [_ACTIVE]

    @pytest.mark.parametrize(("path", "repos_of"), _ENDPOINTS)
    def test_inactive_returns_only_stopped_apps(self, client, seeded, path, repos_of):
        with patch(_CFG, _STOPPED):
            resp = client.get(path, params={"operating": "inactive"}, headers=_HEADERS)
        assert resp.status_code == 200
        assert repos_of(resp.json()) == [_STOPPED]

    @pytest.mark.parametrize(("path", "repos_of"), _ENDPOINTS)
    def test_default_and_all_return_everything(self, client, seeded, path, repos_of):
        with patch(_CFG, _STOPPED):
            default = client.get(path, headers=_HEADERS)
            everything = client.get(path, params={"operating": "all"}, headers=_HEADERS)
        assert repos_of(default.json()) == sorted([_ACTIVE, _STOPPED])
        assert repos_of(everything.json()) == sorted([_ACTIVE, _STOPPED])

    @pytest.mark.parametrize(("path", "_repos_of"), _ENDPOINTS)
    def test_rejects_an_unknown_value(self, client, path, _repos_of):
        resp = client.get(path, params={"operating": "bogus"}, headers=_HEADERS)
        assert resp.status_code == 422

    def test_stats_totals_follow_the_filter(self, client, db_session, seeded):
        _code(db_session, _ACTIVE, line=2)
        db_session.commit()
        with patch(_CFG, _STOPPED):
            body = client.get(
                "/api/codescan/stats", params={"operating": "active"}, headers=_HEADERS,
            ).json()
        assert body["total"] == 2
        assert body["repos"] == [{"repo_full_name": _ACTIVE, "count": 2}]
