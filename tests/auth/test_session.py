"""app.auth.session（セッショントークンの発行・検証）のテスト。"""
import os
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")

import jwt  # noqa: E402

from app.auth.session import (  # noqa: E402
    create_session_token,
    decode_session_token,
    refresh_session_token,
)


class TestCreateAndDecodeSessionToken:
    def test_roundtrip(self):
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", "secret"):
            token = create_session_token("octocat")
            assert decode_session_token(token) == "octocat"

    def test_invalid_token_returns_none(self):
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", "secret"):
            assert decode_session_token("not-a-valid-jwt") is None

    def test_wrong_secret_returns_none(self):
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", "secret-a"):
            token = create_session_token("octocat")
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", "secret-b"):
            assert decode_session_token(token) is None

    def test_expired_token_returns_none(self):
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", "secret"):
            expired = jwt.encode(
                {"sub": "octocat", "exp": datetime.now(UTC) - timedelta(hours=1)},
                "secret", algorithm="HS256",
            )
            assert decode_session_token(expired) is None

    def test_no_secret_key_configured_returns_none(self):
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", ""):
            assert decode_session_token("anything") is None


class TestRefreshSessionToken:
    """スライディング更新（Issue #337）: 使うたびに延びるが、ログインからの上限は超えない。"""

    def test_extends_expiry_and_keeps_user(self):
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", "secret"):
            # 残り1時間だけの古いトークン（ログインは1日前）
            now = datetime.now(UTC)
            old = jwt.encode(
                {"sub": "octocat", "exp": now + timedelta(hours=1),
                 "login_at": int((now - timedelta(days=1)).timestamp())},
                "secret", algorithm="HS256",
            )
            new = refresh_session_token(old)

            assert new is not None
            assert decode_session_token(new) == "octocat"
            exp = jwt.decode(new, "secret", algorithms=["HS256"])["exp"]
            # 新しい有効期限は、約7日後まで延びている
            assert exp - now.timestamp() > timedelta(days=6).total_seconds()

    def test_keeps_original_login_time(self):
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", "secret"):
            login = datetime.now(UTC) - timedelta(days=3)
            token = create_session_token("octocat", login_at=login)
            new = refresh_session_token(token)

            assert new is not None
            payload = jwt.decode(new, "secret", algorithms=["HS256"])
            assert payload["login_at"] == int(login.timestamp())

    def test_rejects_when_login_is_older_than_absolute_limit(self):
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", "secret"):
            token = create_session_token(
                "octocat", login_at=datetime.now(UTC) - timedelta(days=31),
            )
            assert refresh_session_token(token) is None

    def test_legacy_token_without_login_at_is_refreshed(self):
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", "secret"):
            legacy = jwt.encode(
                {"sub": "octocat", "exp": datetime.now(UTC) + timedelta(hours=2)},
                "secret", algorithm="HS256",
            )
            new = refresh_session_token(legacy)
            assert new is not None
            assert decode_session_token(new) == "octocat"

    def test_rejects_expired_invalid_and_unconfigured(self):
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", "secret"):
            expired = jwt.encode(
                {"sub": "octocat", "exp": datetime.now(UTC) - timedelta(hours=1)},
                "secret", algorithm="HS256",
            )
            assert refresh_session_token(expired) is None
            assert refresh_session_token("not-a-valid-jwt") is None
            no_sub = jwt.encode(
                {"exp": datetime.now(UTC) + timedelta(hours=1)}, "secret", algorithm="HS256",
            )
            assert refresh_session_token(no_sub) is None
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", ""):
            assert refresh_session_token("anything") is None
