"""app.auth.github_router（GitHub ログイン・交換コード）のテスト。"""
import os
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")


from app.auth.account_store import get_account  # noqa: E402
from app.auth.session import create_session_token  # noqa: E402
from app.depscan.models import UserScan  # noqa: E402

_NOW = datetime.now(UTC)


class TestGithubLogin:
    def test_returns_503_when_not_configured(self, client):
        with patch("app.auth.github_router.settings.GITHUB_OAUTH_CLIENT_ID", ""):
            res = client.get("/auth/github/login", follow_redirects=False)
        assert res.status_code == 503

    def test_redirects_to_github_and_sets_state_cookie(self, client):
        with patch("app.auth.github_router.settings.GITHUB_OAUTH_CLIENT_ID", "client-123"):
            res = client.get("/auth/github/login", follow_redirects=False)
        assert res.status_code == 302
        assert res.headers["location"].startswith("https://github.com/login/oauth/authorize?")
        assert "gh_oauth_state" in res.cookies


class TestGithubCallback:
    def test_missing_state_cookie_returns_400(self, client):
        with patch("app.auth.github_router.settings.GITHUB_OAUTH_CLIENT_ID", "client-123"), \
             patch("app.auth.github_router.settings.GITHUB_OAUTH_CLIENT_SECRET", "secret"):
            res = client.get(
                "/auth/github/callback?code=abc&state=xyz", follow_redirects=False,
            )
        assert res.status_code == 400

    def test_mismatched_state_returns_400(self, client):
        client.cookies.set("gh_oauth_state", "expected-state")
        with patch("app.auth.github_router.settings.GITHUB_OAUTH_CLIENT_ID", "client-123"), \
             patch("app.auth.github_router.settings.GITHUB_OAUTH_CLIENT_SECRET", "secret"):
            res = client.get(
                "/auth/github/callback?code=abc&state=different-state", follow_redirects=False,
            )
        assert res.status_code == 400

    def test_success_redirects_with_token_and_starts_scan(self, client):
        client.cookies.set("gh_oauth_state", "matching-state")
        with patch("app.auth.github_router.settings.GITHUB_OAUTH_CLIENT_ID", "client-123"), \
             patch("app.auth.github_router.settings.GITHUB_OAUTH_CLIENT_SECRET", "secret"), \
             patch("app.auth.github_router.settings.SESSION_SECRET_KEY", "test-secret"), \
             patch(
                 "app.auth.github_router.settings.FRONTEND_URL", "https://dashboard.example.com",
             ), \
             patch(
                 "app.auth.github_router.exchange_code_for_token", return_value="gho_abc",
             ), \
             patch(
                 "app.auth.github_router.get_authenticated_user_login", return_value="octocat",
             ), \
             patch("app.auth.github_router.threading.Thread") as mock_thread_cls:
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
        with patch("app.auth.github_router.settings.GITHUB_OAUTH_CLIENT_ID", "client-123"), \
             patch("app.auth.github_router.settings.GITHUB_OAUTH_CLIENT_SECRET", "secret"), \
             patch("app.auth.github_router.settings.SESSION_SECRET_KEY", "test-secret"), \
             patch(
                 "app.auth.github_router.settings.FRONTEND_URL", "https://dashboard.example.com",
             ), \
             patch(
                 "app.auth.github_router.exchange_code_for_token", return_value="gho_abc",
             ), \
             patch(
                 "app.auth.github_router.get_authenticated_user_login", return_value="octocat",
             ), \
             patch("app.auth.github_router.threading.Thread") as mock_thread_cls:
            res = client.get(
                "/auth/github/callback?code=abc&state=matching-state", follow_redirects=False,
            )

        assert res.status_code == 302
        mock_thread_cls.assert_not_called()

    def test_persists_encrypted_access_token(self, client, db_session):
        """ログインのたびにアクセストークンを暗号化してUserAccountへ保存する（Issue #227）。"""
        client.cookies.set("gh_oauth_state", "matching-state")
        with patch("app.auth.github_router.settings.GITHUB_OAUTH_CLIENT_ID", "client-123"), \
             patch("app.auth.github_router.settings.GITHUB_OAUTH_CLIENT_SECRET", "secret"), \
             patch("app.auth.github_router.settings.SESSION_SECRET_KEY", "test-secret"), \
             patch(
                 "app.auth.github_router.settings.FRONTEND_URL", "https://dashboard.example.com",
             ), \
             patch(
                 "app.auth.github_router.exchange_code_for_token", return_value="gho_abc",
             ), \
             patch(
                 "app.auth.github_router.get_authenticated_user_login", return_value="octocat",
             ), \
             patch("app.auth.github_router.threading.Thread"):
            res = client.get(
                "/auth/github/callback?code=abc&state=matching-state", follow_redirects=False,
            )

        assert res.status_code == 302
        account = get_account(db_session, "octocat")
        assert account is not None
        assert account.github_access_token_encrypted != "gho_abc"  # 平文で保存しない



class TestExchange:
    def test_exchanges_valid_code_for_token(self, client):
        with patch("app.auth.github_router.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("octocat")
            from app.auth.github_router import _store_exchange_code

            code = _store_exchange_code(token)
            res = client.post("/auth/exchange", json={"code": code})

        assert res.status_code == 200
        body = res.json()
        assert body["username"] == "octocat"
        assert body["token"] == token

    def test_code_is_single_use(self, client):
        with patch("app.auth.github_router.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("octocat")
            from app.auth.github_router import _store_exchange_code

            code = _store_exchange_code(token)
            first = client.post("/auth/exchange", json={"code": code})
            second = client.post("/auth/exchange", json={"code": code})

        assert first.status_code == 200
        assert second.status_code == 400

    def test_rejects_unknown_code(self, client):
        res = client.post("/auth/exchange", json={"code": "not-a-real-code"})
        assert res.status_code == 400

    def test_rejects_expired_code(self, client):
        with patch("app.auth.github_router.settings.SESSION_SECRET_KEY", "test-secret"):
            token = create_session_token("octocat")
            from app.auth.github_router import _pending_exchange_codes, _store_exchange_code

            code = _store_exchange_code(token)
            # 発行済みコードの有効期限を過去に書き換えて期限切れを再現する
            _pending_exchange_codes[code] = (token, 0.0)
            res = client.post("/auth/exchange", json={"code": code})

        assert res.status_code == 400


class TestRefresh:
    """POST /auth/refresh: セッションJWTの有効期間を延長する（Issue #337）。"""

    def test_returns_new_token_for_valid_session(self, client):
        with (
            patch("app.auth.github_router.settings.SESSION_SECRET_KEY", "test-secret"),
            patch("app.auth.session.settings.SESSION_SECRET_KEY", "test-secret"),
        ):
            token = create_session_token("octocat")
            headers = {"Authorization": f"Bearer {token}"}
            res = client.post("/auth/refresh", headers=headers)

        assert res.status_code == 200
        body = res.json()
        assert body["username"] == "octocat"
        assert body["token"]

    def test_rejects_missing_authorization(self, client):
        assert client.post("/auth/refresh").status_code == 401

    def test_rejects_invalid_token(self, client):
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", "test-secret"):
            res = client.post("/auth/refresh", headers={"Authorization": "Bearer nope"})
        assert res.status_code == 401
