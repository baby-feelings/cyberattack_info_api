"""app.auth.account_router（スキャン進捗・Slack通知設定）のテスト。"""
import os
from datetime import UTC, datetime
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")


from app.auth.session import create_session_token  # noqa: E402

_NOW = datetime.now(UTC)


class TestScanStatus:
    def test_requires_bearer_token(self, client):
        res = client.get("/auth/scan-status")
        assert res.status_code == 401

    def test_rejects_invalid_token(self, client):
        res = client.get(
            "/auth/scan-status", headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert res.status_code == 401

    def test_returns_not_started_when_no_scan_yet(self, client):
        with patch("app.core.config.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("octocat")
            res = client.get(
                "/auth/scan-status", headers={"Authorization": f"Bearer {token}"},
            )
        assert res.status_code == 200
        assert res.json() == {"username": "octocat", "status": "not_started"}


class TestNotificationSettings:
    """GET/PUT/DELETE /auth/notification-settings（Issue #227）のテスト。"""

    def _auth_header(self):
        token = create_session_token("octocat")
        return {"Authorization": f"Bearer {token}"}

    def test_get_requires_bearer_token(self, client):
        res = client.get("/auth/notification-settings")
        assert res.status_code == 401

    def test_get_returns_unregistered_when_no_account(self, client):
        res = client.get("/auth/notification-settings", headers=self._auth_header())
        assert res.status_code == 200
        assert res.json() == {"slack_webhook_url": None, "notifications_enabled": True}

    def test_put_rejects_invalid_url_format(self, client):
        res = client.put(
            "/auth/notification-settings",
            headers=self._auth_header(),
            json={"slack_webhook_url": "https://evil.example.com/x"},
        )
        assert res.status_code == 400

    def test_put_rejects_when_test_send_fails(self, client):
        with patch("app.auth.account_router.send_test_notification", return_value=False):
            res = client.put(
                "/auth/notification-settings",
                headers=self._auth_header(),
                json={"slack_webhook_url": "https://hooks.slack.com/services/x"},
            )
        assert res.status_code == 400

    def test_put_registers_webhook_after_successful_test_send(self, client, db_session):
        from app.auth.account_store import upsert_user_token

        upsert_user_token(db_session, "octocat", "gho_abc")

        with patch(
            "app.auth.account_router.send_test_notification", return_value=True,
        ) as mock_test:
            res = client.put(
                "/auth/notification-settings",
                headers=self._auth_header(),
                json={"slack_webhook_url": "https://hooks.slack.com/services/x"},
            )
        assert res.status_code == 200
        assert res.json() == {
            "slack_webhook_url": "https://hooks.slack.com/services/x",
            "notifications_enabled": True,
        }
        mock_test.assert_called_once_with("https://hooks.slack.com/services/x", "octocat")

        get_res = client.get("/auth/notification-settings", headers=self._auth_header())
        assert get_res.json()["slack_webhook_url"] == "https://hooks.slack.com/services/x"

    def test_put_without_prior_login_returns_400(self, client):
        """UserAccount行が無い（一度もログインしていない）場合は400（通常到達しない防御的経路）。"""
        with patch("app.auth.account_router.send_test_notification", return_value=True):
            res = client.put(
                "/auth/notification-settings",
                headers=self._auth_header(),
                json={"slack_webhook_url": "https://hooks.slack.com/services/x"},
            )
        assert res.status_code == 400

    def test_delete_clears_webhook(self, client, db_session):
        from app.auth.account_store import set_slack_webhook, upsert_user_token

        upsert_user_token(db_session, "octocat", "gho_abc")
        set_slack_webhook(db_session, "octocat", "https://hooks.slack.com/services/x")

        res = client.delete("/auth/notification-settings", headers=self._auth_header())
        assert res.status_code == 200
        assert res.json()["slack_webhook_url"] is None

        get_res = client.get("/auth/notification-settings", headers=self._auth_header())
        assert get_res.json()["slack_webhook_url"] is None
