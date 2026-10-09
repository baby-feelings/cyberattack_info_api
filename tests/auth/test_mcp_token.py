"""app.auth.mcp_token（MCP トークン JWT の発行・検証）のテスト。"""
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")
os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret-key-for-pytest")

import jwt  # noqa: E402

from app.auth.mcp_token import McpClaims, create_mcp_token, verify_mcp_token  # noqa: E402
from app.auth.session import create_session_token, decode_session_token  # noqa: E402
from app.core.config import settings  # noqa: E402

_AUD = "cyberattack-info-mcp"


def _future() -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=1)


def _encode(payload: dict, key: str | None = None) -> str:
    return jwt.encode(payload, key or settings.SESSION_SECRET_KEY, algorithm="HS256")


class TestMcpTokenJwt:
    def test_roundtrip_carries_username_and_token_id(self):
        token = create_mcp_token("alice", "tok-1", _future())
        assert verify_mcp_token(token) == McpClaims(username="alice", token_id="tok-1")

    def test_session_token_is_not_accepted_as_mcp_token(self):
        assert verify_mcp_token(create_session_token("alice")) is None

    def test_mcp_token_is_not_accepted_as_session_token(self):
        # 長期有効の MCP トークンが、ダッシュボードのセッションとして使い回されないこと
        assert decode_session_token(create_mcp_token("alice", "tok-1", _future())) is None

    def test_expired_token_is_rejected(self):
        past = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert verify_mcp_token(create_mcp_token("alice", "tok-1", past)) is None

    def test_wrong_signature_is_rejected(self):
        token = _encode(
            {"sub": "alice", "jti": "t", "aud": _AUD, "exp": _future()},
            key="another-secret-key-1234567890-abcdef",
        )
        assert verify_mcp_token(token) is None

    def test_garbage_is_rejected(self):
        assert verify_mcp_token("not-a-token") is None

    def test_rejected_when_secret_not_configured(self):
        token = create_mcp_token("alice", "tok-1", _future())
        with patch("app.auth.mcp_token.settings.SESSION_SECRET_KEY", ""):
            assert verify_mcp_token(token) is None

    def test_legacy_token_without_jti_is_rejected(self):
        # 台帳に載らず個別に失効できない旧形式（jti なし）は受け付けない
        token = _encode({"sub": "alice", "aud": _AUD, "exp": _future()})
        assert verify_mcp_token(token) is None

    def test_empty_subject_or_jti_is_rejected(self):
        assert verify_mcp_token(_encode(
            {"sub": "", "jti": "t", "aud": _AUD, "exp": _future()})) is None
        assert verify_mcp_token(_encode(
            {"sub": "alice", "jti": "", "aud": _AUD, "exp": _future()})) is None
