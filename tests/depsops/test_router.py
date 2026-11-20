"""DEPSOPS の一覧・統計 API と、手動実行（POST /admin/dependabot-ops）のテスト。
"""
import os
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")


from app.depsops.models import DependabotPrLog  # noqa: E402

TEST_API_KEY = "test-api-key-for-pytest"
HEADERS = {"X-API-KEY": TEST_API_KEY}


def _mock_httpx_client(get_return=None, put_return=None, post_return=None, delete_return=None):
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    if get_return is not None:
        mock_client.get = MagicMock(return_value=get_return)
    if put_return is not None:
        mock_client.put = MagicMock(return_value=put_return)
    if post_return is not None:
        mock_client.post = MagicMock(return_value=post_return)
    if delete_return is not None:
        mock_client.delete = MagicMock(return_value=delete_return)
    return mock_client


def _mock_response(json_data, status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.raise_for_status = MagicMock()
    resp.json.return_value = json_data
    return resp


# ──────────────────────────────────────────────────────────────
# GET /api/depsops
# ──────────────────────────────────────────────────────────────


class TestListDepsops:
    def test_requires_auth(self, client):
        res = client.get("/api/depsops")
        assert res.status_code == 403

    def test_returns_recent_prs_sorted_desc(self, client, db_session):
        db_session.add_all([
            DependabotPrLog(
                repo_full_name="u/r1", pr_number=1, title="bump a", action="merged",
                processed_at=datetime(2026, 6, 1, tzinfo=UTC),
            ),
            DependabotPrLog(
                repo_full_name="u/r2", pr_number=2, title="bump b", action="flagged",
                reason="メジャー", processed_at=datetime(2026, 6, 2, tzinfo=UTC),
            ),
        ])
        db_session.commit()

        res = client.get("/api/depsops", headers=HEADERS)

        assert res.status_code == 200
        body = res.json()
        assert body["total"] == 2
        assert [item["pr_number"] for item in body["data"]] == [2, 1]
        assert body["data"][0]["reason"] == "メジャー"

    def test_filters_by_action(self, client, db_session):
        db_session.add_all([
            DependabotPrLog(
                repo_full_name="u/r1", pr_number=1, title="bump a", action="merged",
                processed_at=datetime(2026, 6, 1, tzinfo=UTC),
            ),
            DependabotPrLog(
                repo_full_name="u/r1", pr_number=2, title="bump b", action="flagged",
                reason="メジャー", processed_at=datetime(2026, 6, 2, tzinfo=UTC),
            ),
        ])
        db_session.commit()

        res = client.get("/api/depsops?action=flagged", headers=HEADERS)

        assert res.status_code == 200
        body = res.json()
        assert body["total"] == 1
        assert body["data"][0]["action"] == "flagged"

    def test_filters_by_repo(self, client, db_session):
        db_session.add_all([
            DependabotPrLog(
                repo_full_name="u/r1", pr_number=1, title="bump a", action="merged",
                processed_at=datetime(2026, 6, 1, tzinfo=UTC),
            ),
            DependabotPrLog(
                repo_full_name="u/r2", pr_number=1, title="bump a", action="merged",
                processed_at=datetime(2026, 6, 1, tzinfo=UTC),
            ),
        ])
        db_session.commit()

        res = client.get("/api/depsops?repo=u/r2", headers=HEADERS)

        assert res.status_code == 200
        body = res.json()
        assert body["total"] == 1
        assert body["data"][0]["repo_full_name"] == "u/r2"


# ──────────────────────────────────────────────────────────────
# GET /api/depsops/stats
# ──────────────────────────────────────────────────────────────


class TestDepsopsStats:
    def test_requires_auth(self, client):
        res = client.get("/api/depsops/stats")
        assert res.status_code == 403

    def test_counts_only_latest_flagged_per_pr(self, client, db_session):
        """同じPRについて複数回判定記録があっても、最新の状態のみを数える。"""
        db_session.add_all([
            # u/r1#1: 古い判定はflagged、最新はmerged → 未解決に数えない
            DependabotPrLog(
                repo_full_name="u/r1", pr_number=1, title="bump a", action="flagged",
                reason="メジャー", processed_at=datetime(2026, 6, 1, tzinfo=UTC),
            ),
            DependabotPrLog(
                repo_full_name="u/r1", pr_number=1, title="bump a", action="merged",
                processed_at=datetime(2026, 6, 2, tzinfo=UTC),
            ),
            # u/r1#2: 最新がflagged → 未解決として数える
            DependabotPrLog(
                repo_full_name="u/r1", pr_number=2, title="bump b", action="flagged",
                reason="メジャー", processed_at=datetime(2026, 6, 1, tzinfo=UTC),
            ),
            # u/r2#1: 最新がflagged → 別リポジトリとして数える
            DependabotPrLog(
                repo_full_name="u/r2", pr_number=1, title="bump c", action="flagged",
                reason="メジャー", processed_at=datetime(2026, 6, 1, tzinfo=UTC),
            ),
        ])
        db_session.commit()

        res = client.get("/api/depsops/stats", headers=HEADERS)

        assert res.status_code == 200
        repos = {r["repo_full_name"]: r["count"] for r in res.json()["repos"]}
        assert repos == {"u/r1": 1, "u/r2": 1}

    def test_empty_when_no_records(self, client):
        res = client.get("/api/depsops/stats", headers=HEADERS)
        assert res.status_code == 200
        assert res.json()["repos"] == []


# ──────────────────────────────────────────────────────────────
# POST /admin/dependabot-ops
# ──────────────────────────────────────────────────────────────


class TestAdminDependabotOps:
    def test_requires_auth(self, client):
        res = client.post("/admin/dependabot-ops")
        assert res.status_code == 403

    def test_trigger_returns_202(self, client):
        with patch("app.depsops.router.run_dependabot_ops", return_value=(0, 0, 0)):
            res = client.post("/admin/dependabot-ops", headers=HEADERS)
        assert res.status_code == 202
        assert "background" in res.json()["message"].lower()

    def test_force_query_param_is_passed_through(self, client):
        """?force=true が run_dependabot_ops(force=True) に渡ること（Issue #239）。"""
        with patch(
            "app.depsops.router.run_in_background", side_effect=lambda name, fn: fn(),
        ), patch(
            "app.depsops.router.run_dependabot_ops", return_value=(0, 0, 0),
        ) as mock_run:
            res = client.post("/admin/dependabot-ops?force=true", headers=HEADERS)
        assert res.status_code == 202
        mock_run.assert_called_once_with(force=True)
