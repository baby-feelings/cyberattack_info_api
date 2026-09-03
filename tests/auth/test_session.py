"""app.auth.session（セッショントークンの発行・検証）のテスト。"""
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")

import jwt  # noqa: E402

from app.auth.session import create_session_token, decode_session_token  # noqa: E402


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
                {"sub": "octocat", "exp": datetime.now(timezone.utc) - timedelta(hours=1)},
                "secret", algorithm="HS256",
            )
            assert decode_session_token(expired) is None

    def test_no_secret_key_configured_returns_none(self):
        with patch("app.auth.session.settings.SESSION_SECRET_KEY", ""):
            assert decode_session_token("anything") is None
