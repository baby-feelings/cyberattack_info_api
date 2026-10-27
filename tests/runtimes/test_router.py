"""app.runtimes.router（/api/runtimes 系と、手動実行 /admin/runtime-crawl）のテスト。"""
import os
from datetime import date
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.auth.session import create_session_token  # noqa: E402
from app.runtimes.models import RepoRuntime, RuntimeRelease  # noqa: E402

HEADERS = {"X-API-KEY": "test-api-key-for-pytest"}
_TODAY = date(2026, 10, 27)


def _today():
    """判定の基準日を固定する（サポート期限までの日数を安定させる）。"""
    return patch("app.runtimes.router._today", return_value=_TODAY)


def _release(runtime, cycle, latest, *, eol=None, is_eol=False, lts=False, released=None):
    return RuntimeRelease(
        runtime=runtime, cycle=cycle, latest_version=latest, eol_date=eol,
        is_eol=is_eol, is_lts=lts, release_date=released,
    )


def _use(repo, runtime, cycle, path="Dockerfile", pinned=True):
    return RepoRuntime(
        repo_full_name=repo, runtime=runtime, cycle=cycle, source_path=path, pinned=pinned,
    )


def _seed(db_session):
    db_session.add_all([
        # 3.15 は公開から 18 日で、まだ推奨にならない（推奨は、公開から 6 か月以上の 3.14）
        _release("python", "3.15", "3.15.2", eol=date(2031, 10, 31), released=date(2026, 10, 9)),
        _release("python", "3.14", "3.14.10", eol=date(2030, 10, 31), released=date(2025, 10, 7)),
        _release("python", "3.13", "3.13.17", eol=date(2029, 10, 31)),
        _release("python", "3.10", "3.10.20", eol=date(2026, 10, 1), is_eol=True),
        _release("nodejs", "24", "24.22.1", eol=date(2028, 4, 30), lts=True),
        _release("nodejs", "22", "22.17.1", eol=date(2027, 4, 30), lts=True),
        _use("alice/api", "python", "3.10"),                      # eol
        _use("alice/api", "nodejs", "22", "package.json", False),  # reference
        _use("alice/web", "nodejs", "24", ".nvmrc"),               # latest
        _use("alice/web", "python", "3.13"),                       # update_available
        _use("bob/app", "python", "3.13"),
    ])
    db_session.commit()


class TestListRuntimes:
    def test_requires_auth(self, client):
        assert client.get("/api/runtimes").status_code == 403

    def test_returns_status_with_most_urgent_first(self, client, db_session):
        _seed(db_session)
        with _today():
            res = client.get("/api/runtimes", headers=HEADERS)

        assert res.status_code == 200
        body = res.json()
        assert body["total"] == 5
        states = [row["state"] for row in body["data"]]
        assert states == ["eol", "update_available", "update_available", "latest", "reference"]
        first = body["data"][0]
        assert (first["repo_full_name"], first["runtime"], first["cycle"]) == (
            "alice/api", "python", "3.10")
        assert first["runtime_label"] == "Python"
        assert first["eol_date"] == "2026-10-01"
        assert first["days_to_eol"] == -26
        assert first["recommended_cycle"] == "3.14"

    def test_needs_action_filters_to_actionable_states(self, client, db_session):
        _seed(db_session)
        with _today():
            res = client.get("/api/runtimes?needs_action=true", headers=HEADERS)
        assert {row["state"] for row in res.json()["data"]} == {"eol", "update_available"}

    def test_filters_by_repo_and_runtime(self, client, db_session):
        _seed(db_session)
        with _today():
            by_repo = client.get("/api/runtimes?repo=alice/web", headers=HEADERS)
            by_runtime = client.get("/api/runtimes?runtime=nodejs", headers=HEADERS)
            unknown_runtime = client.get("/api/runtimes?runtime=ruby", headers=HEADERS)
        assert {r["repo_full_name"] for r in by_repo.json()["data"]} == {"alice/web"}
        assert {r["runtime"] for r in by_runtime.json()["data"]} == {"nodejs"}
        # 未対応の言語名は無視して、絞り込まない（500 にしない）
        assert unknown_runtime.json()["total"] == 5

    def test_operating_filter(self, client, db_session):
        _seed(db_session)
        with _today(), patch("app.core.operating_status.settings.INACTIVE_REPOS", "bob/app"):
            active = client.get("/api/runtimes?operating=active", headers=HEADERS)
            inactive = client.get("/api/runtimes?operating=inactive", headers=HEADERS)
        assert "bob/app" not in {r["repo_full_name"] for r in active.json()["data"]}
        assert {r["repo_full_name"] for r in inactive.json()["data"]} == {"bob/app"}

    def test_session_token_sees_only_own_repos(self, client, db_session):
        _seed(db_session)
        with _today(), patch("app.auth.session.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("alice")
            res = client.get("/api/runtimes", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 200
        assert {r["repo_full_name"] for r in res.json()["data"]} == {"alice/api", "alice/web"}

    def test_session_token_cannot_query_other_users_repo(self, client, db_session):
        _seed(db_session)
        with _today(), patch("app.auth.session.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("alice")
            res = client.get(
                "/api/runtimes?repo=bob/app", headers={"Authorization": f"Bearer {token}"},
            )
        assert res.json()["data"] == []

    def test_owner_name_with_underscore_does_not_match_other_owners(self, client, db_session):
        """`_` は LIKE のワイルドカードのため、前方一致で絞る（他のオーナーを見せない）。"""
        db_session.add_all([
            _release("python", "3.13", "3.13.17"),
            _use("a_b/app", "python", "3.13"),
            _use("aXb/app", "python", "3.13"),
        ])
        db_session.commit()
        with _today(), patch("app.auth.session.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("a_b")
            res = client.get("/api/runtimes", headers={"Authorization": f"Bearer {token}"})
        assert {r["repo_full_name"] for r in res.json()["data"]} == {"a_b/app"}


class TestListRepos:
    def test_counts_total_and_actionable_per_repo(self, client, db_session):
        _seed(db_session)
        with _today():
            res = client.get("/api/runtimes/repos", headers=HEADERS)
        repos = res.json()["repos"]
        assert [(r["repo_full_name"], r["total"], r["needs_action"]) for r in repos] == [
            ("alice/api", 2, 1),   # 対応が必要なリポジトリが先頭
            ("alice/web", 2, 1),
            ("bob/app", 1, 1),
        ]

    def test_requires_auth(self, client):
        assert client.get("/api/runtimes/repos").status_code == 403


class TestListReleases:
    def test_marks_recommended_cycle_per_runtime(self, client, db_session):
        _seed(db_session)
        with _today():
            res = client.get("/api/runtimes/releases", headers=HEADERS)

        assert res.status_code == 200
        data = res.json()["data"]
        python = [r for r in data if r["runtime"] == "python"]
        assert [r["cycle"] for r in python] == ["3.15", "3.14", "3.13", "3.10"]  # 新しい系列が先頭
        assert [r["cycle"] for r in python if r["recommended"]] == ["3.14"]
        node = [r for r in data if r["runtime"] == "nodejs"]
        assert [r["cycle"] for r in node if r["recommended"]] == ["24"]
        assert python[0]["eol_date"] == "2031-10-31"

    def test_requires_auth(self, client):
        assert client.get("/api/runtimes/releases").status_code == 403


class TestTriggerCrawl:
    def test_requires_api_key(self, client):
        assert client.post("/admin/runtime-crawl").status_code == 403

    def test_starts_in_background(self, client):
        with patch("app.runtimes.router.run_in_background") as mock_bg:
            res = client.post("/admin/runtime-crawl", headers=HEADERS)
        assert res.status_code == 202
        assert mock_bg.call_args[0][0] == "RUNTIME"

    def test_force_flag_is_forwarded(self, client):
        with (
            patch("app.runtimes.router.run_in_background") as mock_bg,
            patch("app.runtimes.router.fetch_and_scan_runtimes") as mock_scan,
        ):
            client.post("/admin/runtime-crawl?force=true", headers=HEADERS)
            mock_bg.call_args[0][1]()
        mock_scan.assert_called_once_with(force=True)
