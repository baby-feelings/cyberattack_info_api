"""app.sla.router（GET /api/sla と、手動実行 /admin/sla-digest）のテスト。"""
import os
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.auth.session import create_session_token  # noqa: E402
from app.depscan.models import DependencyFinding  # noqa: E402

HEADERS = {"X-API-KEY": "test-api-key-for-pytest"}


def _finding(repo, osv_id, *, severity="HIGH", detected_days_ago, resolved_days_ago=None):
    now = datetime.now(UTC)
    return DependencyFinding(
        repo_full_name=repo, ecosystem="npm", package_name=f"pkg-{osv_id}",
        installed_version="1.0.0", osv_id=osv_id, severity=severity, summary="s",
        fixed_versions=[], cve_ids=[], manifest_path="package-lock.json",
        detected_at=now - timedelta(days=detected_days_ago),
        resolved_at=(
            now - timedelta(days=resolved_days_ago) if resolved_days_ago is not None else None
        ),
    )


def _seed(db_session):
    db_session.add_all([
        _finding("alice/api", "a1", detected_days_ago=45),                       # 15日超過
        _finding("alice/api", "a2", detected_days_ago=5),                        # 期限内
        _finding("alice/api", "a3", detected_days_ago=20, resolved_days_ago=10),  # 解決（10日）
        _finding("bob/app", "b1", severity="CRITICAL", detected_days_ago=30),    # 23日超過
    ])
    db_session.commit()


class TestGetSlaReport:
    def test_requires_authentication(self, client):
        assert client.get("/api/sla").status_code in (401, 403)

    def test_returns_summary_policy_severity_repo_and_overdue(self, client, db_session):
        _seed(db_session)

        res = client.get("/api/sla", headers=HEADERS)

        assert res.status_code == 200
        body = res.json()
        assert body["summary"]["overdue"] == 2
        assert body["summary"]["open_with_deadline"] == 3
        assert body["summary"]["resolved"] == 1
        assert body["summary"]["mttr_days"] == 10.0
        assert body["policy"] == {
            "critical_days": 7, "high_days": 30, "medium_days": 90, "kev_days": 7,
            "excluded_osv_ids": [],
        }
        assert body["mttr_window_days"] == 90
        # 超過日数が多い順（bob の CRITICAL 23日 → alice の HIGH 15日）
        assert [i["osv_id"] for i in body["overdue"]] == ["b1", "a1"]
        assert [s["severity"] for s in body["by_severity"]] == ["CRITICAL", "HIGH"]
        # 期限超過は同数（各1件）のため、未解決が多い alice が先
        assert [r["repo_full_name"] for r in body["by_repo"]] == ["alice/api", "bob/app"]

    def test_filters_by_repo_and_owner(self, client, db_session):
        _seed(db_session)

        by_repo = client.get("/api/sla?repo=alice/api", headers=HEADERS).json()
        by_owner = client.get("/api/sla?owner=bob", headers=HEADERS).json()

        assert [i["repo_full_name"] for i in by_repo["overdue"]] == ["alice/api"]
        assert [i["repo_full_name"] for i in by_owner["overdue"]] == ["bob/app"]

    def test_operating_filter(self, client, db_session):
        _seed(db_session)

        with patch("app.core.operating_status.settings.INACTIVE_REPOS", "bob/app"):
            active = client.get("/api/sla?operating=active", headers=HEADERS).json()
            inactive = client.get("/api/sla?operating=inactive", headers=HEADERS).json()

        assert {i["repo_full_name"] for i in active["overdue"]} == {"alice/api"}
        assert {i["repo_full_name"] for i in inactive["overdue"]} == {"bob/app"}

    def test_window_days_limits_the_resolved_period(self, client, db_session):
        _seed(db_session)

        # 解決は 10 日前。直近 5 日の集計には含まれない
        body = client.get("/api/sla?window_days=5", headers=HEADERS).json()

        assert body["summary"]["resolved"] == 0
        assert body["summary"]["mttr_days"] is None
        assert body["mttr_window_days"] == 5

    def test_window_days_is_bounded_by_the_retention_period(self, client):
        assert client.get("/api/sla?window_days=0", headers=HEADERS).status_code == 422
        assert client.get("/api/sla?window_days=181", headers=HEADERS).status_code == 422

    def test_session_token_sees_only_own_repos(self, client, db_session):
        _seed(db_session)
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("alice")
            res = client.get("/api/sla", headers={"Authorization": f"Bearer {token}"})

        assert res.status_code == 200
        assert {i["repo_full_name"] for i in res.json()["overdue"]} == {"alice/api"}

    def test_session_token_cannot_query_other_users_repo(self, client, db_session):
        _seed(db_session)
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("alice")
            res = client.get("/api/sla?repo=bob/app", headers={"Authorization": f"Bearer {token}"})

        assert res.status_code == 403

    def test_empty_database(self, client):
        body = client.get("/api/sla", headers=HEADERS).json()

        assert body["summary"]["overdue"] == 0
        assert body["overdue"] == []


class TestTriggerSlaDigest:
    def test_requires_the_admin_api_key(self, client):
        assert client.post("/admin/sla-digest").status_code in (401, 403)

    def test_starts_the_digest_in_the_background(self, client):
        with patch("app.sla.router.run_in_background") as mock_run:
            res = client.post("/admin/sla-digest", headers=HEADERS)

        assert res.status_code == 202
        mock_run.assert_called_once()
        assert mock_run.call_args[0][0] == "SLA_DIGEST"
