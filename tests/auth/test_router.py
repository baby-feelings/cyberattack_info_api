"""app.auth.router（GitHub ログイン API）のテスト。"""
import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")

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
        assert "depscan_user=octocat" in location
        assert "depscan_token=" in location
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
