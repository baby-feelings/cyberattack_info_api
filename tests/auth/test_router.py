"""app.auth.router（GitHub ログイン API）のテスト。"""
import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")

from app.auth.account_store import get_account  # noqa: E402
from app.auth.session import create_session_token  # noqa: E402
from app.depscan.models import UserScan  # noqa: E402

_NOW = datetime.now(timezone.utc)


class TestGithubLogin:
    def test_returns_503_when_not_configured(self, client):
        with patch("app.auth.router.settings.GITHUB_OAUTH_CLIENT_ID", ""):
            res = client.get("/auth/github/login", follow_redirects=False)
        assert res.status_code == 503

    def test_redirects_to_github_and_sets_state_cookie(self, client):
        with patch("app.auth.router.settings.GITHUB_OAUTH_CLIENT_ID", "client-123"):
            res = client.get("/auth/github/login", follow_redirects=False)
        assert res.status_code == 302
        assert res.headers["location"].startswith("https://github.com/login/oauth/authorize?")
        assert "gh_oauth_state" in res.cookies


class TestGithubCallback:
    def test_missing_state_cookie_returns_400(self, client):
        with patch("app.auth.router.settings.GITHUB_OAUTH_CLIENT_ID", "client-123"), \
             patch("app.auth.router.settings.GITHUB_OAUTH_CLIENT_SECRET", "secret"):
            res = client.get(
                "/auth/github/callback?code=abc&state=xyz", follow_redirects=False,
            )
        assert res.status_code == 400

    def test_mismatched_state_returns_400(self, client):
        client.cookies.set("gh_oauth_state", "expected-state")
        with patch("app.auth.router.settings.GITHUB_OAUTH_CLIENT_ID", "client-123"), \
             patch("app.auth.router.settings.GITHUB_OAUTH_CLIENT_SECRET", "secret"):
            res = client.get(
                "/auth/github/callback?code=abc&state=different-state", follow_redirects=False,
            )
        assert res.status_code == 400

    def test_success_redirects_with_token_and_starts_scan(self, client):
        client.cookies.set("gh_oauth_state", "matching-state")
        with patch("app.auth.router.settings.GITHUB_OAUTH_CLIENT_ID", "client-123"), \
             patch("app.auth.router.settings.GITHUB_OAUTH_CLIENT_SECRET", "secret"), \
             patch("app.auth.router.settings.SESSION_SECRET_KEY", "test-secret"), \
             patch("app.auth.router.settings.FRONTEND_URL", "https://dashboard.example.com"), \
             patch(
                 "app.auth.router.exchange_code_for_token", return_value="gho_abc",
             ), \
             patch(
                 "app.auth.router.get_authenticated_user_login", return_value="octocat",
             ), \
             patch("app.auth.router.threading.Thread") as mock_thread_cls:
            mock_thread = MagicMock()
            mock_thread_cls.return_value = mock_thread

            res = client.get(
                "/auth/github/callback?code=abc&state=matching-state", follow_redirects=False,
            )

        assert res.status_code == 302
        location = res.headers["location"]
        assert location.startswith("https://dashboard.example.com/?")
        # RFC 9700対策: セッショントークンそのものをURLクエリに載せない。
        # 数十秒で失効し一度しか使えない交換コードのみを載せる
        assert "depscan_token=" not in location
        assert "depscan_user=" not in location
        assert "depscan_code=" in location
        mock_thread.start.assert_called_once()
        # バックグラウンドスキャンがログインユーザー本人のトークンで起動されること
        assert mock_thread_cls.call_args.kwargs["args"] == ("octocat", "gho_abc")

    def test_skips_scan_when_recently_scanned(self, client, db_session):
        """直近24時間以内にスキャン済みなら、ログインしても再スキャンを起動しない。"""
        db_session.add(UserScan(
            username="octocat", status="done", repos_scanned=5,
            started_at=_NOW, finished_at=_NOW,
        ))
        db_session.commit()

        client.cookies.set("gh_oauth_state", "matching-state")
        with patch("app.auth.router.settings.GITHUB_OAUTH_CLIENT_ID", "client-123"), \
             patch("app.auth.router.settings.GITHUB_OAUTH_CLIENT_SECRET", "secret"), \
             patch("app.auth.router.settings.SESSION_SECRET_KEY", "test-secret"), \
             patch("app.auth.router.settings.FRONTEND_URL", "https://dashboard.example.com"), \
             patch(
                 "app.auth.router.exchange_code_for_token", return_value="gho_abc",
             ), \
             patch(
                 "app.auth.router.get_authenticated_user_login", return_value="octocat",
             ), \
             patch("app.auth.router.threading.Thread") as mock_thread_cls:
            res = client.get(
                "/auth/github/callback?code=abc&state=matching-state", follow_redirects=False,
            )

        assert res.status_code == 302
        mock_thread_cls.assert_not_called()

    def test_persists_encrypted_access_token(self, client, db_session):
        """ログインのたびにアクセストークンを暗号化してUserAccountへ保存する（Issue #227）。"""
        client.cookies.set("gh_oauth_state", "matching-state")
        with patch("app.auth.router.settings.GITHUB_OAUTH_CLIENT_ID", "client-123"), \
             patch("app.auth.router.settings.GITHUB_OAUTH_CLIENT_SECRET", "secret"), \
             patch("app.auth.router.settings.SESSION_SECRET_KEY", "test-secret"), \
             patch("app.auth.router.settings.FRONTEND_URL", "https://dashboard.example.com"), \
             patch(
                 "app.auth.router.exchange_code_for_token", return_value="gho_abc",
             ), \
             patch(
                 "app.auth.router.get_authenticated_user_login", return_value="octocat",
             ), \
             patch("app.auth.router.threading.Thread"):
            res = client.get(
                "/auth/github/callback?code=abc&state=matching-state", follow_redirects=False,
            )

        assert res.status_code == 302
        account = get_account(db_session, "octocat")
        assert account is not None
        assert account.github_access_token_encrypted != "gho_abc"  # 平文で保存しない


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
        with patch("app.auth.router.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("octocat")
            res = client.get(
                "/auth/scan-status", headers={"Authorization": f"Bearer {token}"},
            )
        assert res.status_code == 200
        assert res.json() == {"username": "octocat", "status": "not_started"}

class TestExchange:
    def test_exchanges_valid_code_for_token(self, client):
        with patch("app.auth.router.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("octocat")
            from app.auth.router import _store_exchange_code

            code = _store_exchange_code(token)
            res = client.post("/auth/exchange", json={"code": code})

        assert res.status_code == 200
        body = res.json()
        assert body["username"] == "octocat"
        assert body["token"] == token

    def test_code_is_single_use(self, client):
        with patch("app.auth.router.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("octocat")
            from app.auth.router import _store_exchange_code

            code = _store_exchange_code(token)
            first = client.post("/auth/exchange", json={"code": code})
            second = client.post("/auth/exchange", json={"code": code})

        assert first.status_code == 200
        assert second.status_code == 400

    def test_rejects_unknown_code(self, client):
        res = client.post("/auth/exchange", json={"code": "not-a-real-code"})
        assert res.status_code == 400

    def test_rejects_expired_code(self, client):
        with patch("app.auth.router.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("octocat")
            from app.auth.router import _pending_exchange_codes, _store_exchange_code

            code = _store_exchange_code(token)
            # 発行済みコードの有効期限を過去に書き換えて期限切れを再現する
            _pending_exchange_codes[code] = (token, 0.0)
            res = client.post("/auth/exchange", json={"code": code})

        assert res.status_code == 400


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
        with patch("app.auth.router.send_test_notification", return_value=False):
            res = client.put(
                "/auth/notification-settings",
                headers=self._auth_header(),
                json={"slack_webhook_url": "https://hooks.slack.com/services/x"},
            )
        assert res.status_code == 400

    def test_put_registers_webhook_after_successful_test_send(self, client, db_session):
        from app.auth.account_store import upsert_user_token

        upsert_user_token(db_session, "octocat", "gho_abc")

        with patch("app.auth.router.send_test_notification", return_value=True) as mock_test:
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
        with patch("app.auth.router.send_test_notification", return_value=True):
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
