"""app.auth.mcp_token と POST /auth/mcp-token のテスト。"""
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")
os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret-key-for-pytest")

import jwt  # noqa: E402

from app.auth.mcp_token import EXPIRES_DAYS, create_mcp_token, verify_mcp_token  # noqa: E402
from app.auth.session import create_session_token, decode_session_token  # noqa: E402
from app.core.config import settings  # noqa: E402


class TestMcpToken:
    def test_roundtrip(self):
        token, expires_at = create_mcp_token("alice")
        assert verify_mcp_token(token) == "alice"
        delta = expires_at - datetime.now(timezone.utc)
        assert timedelta(days=EXPIRES_DAYS - 1) < delta <= timedelta(days=EXPIRES_DAYS)

    def test_session_token_is_not_accepted_as_mcp_token(self):
        assert verify_mcp_token(create_session_token("alice")) is None

    def test_mcp_token_is_not_accepted_as_session_token(self):
        # 30 日有効の MCP トークンが、ダッシュボードのセッションとして使い回されないこと
        token, _ = create_mcp_token("alice")
        assert decode_session_token(token) is None

    def test_expired_token_is_rejected(self):
        payload = {
            "sub": "alice", "aud": "cyberattack-info-mcp",
            "exp": datetime.now(timezone.utc) - timedelta(seconds=1),
        }
        token = jwt.encode(payload, settings.SESSION_SECRET_KEY, algorithm="HS256")
        assert verify_mcp_token(token) is None

    def test_wrong_signature_is_rejected(self):
        payload = {
            "sub": "alice", "aud": "cyberattack-info-mcp",
            "exp": datetime.now(timezone.utc) + timedelta(days=1),
        }
        token = jwt.encode(payload, "another-secret-key-1234567890-abcdef", algorithm="HS256")
        assert verify_mcp_token(token) is None

    def test_garbage_is_rejected(self):
        assert verify_mcp_token("not-a-token") is None

    def test_rejected_when_secret_not_configured(self):
        token, _ = create_mcp_token("alice")
        with patch("app.auth.mcp_token.settings.SESSION_SECRET_KEY", ""):
            assert verify_mcp_token(token) is None

    def test_empty_subject_is_rejected(self):
        payload = {
            "sub": "", "aud": "cyberattack-info-mcp",
            "exp": datetime.now(timezone.utc) + timedelta(days=1),
        }
        token = jwt.encode(payload, settings.SESSION_SECRET_KEY, algorithm="HS256")
        assert verify_mcp_token(token) is None


class TestIssueMcpTokenEndpoint:
    def test_requires_login(self, client):
        assert client.post("/auth/mcp-token").status_code == 401

    def test_api_key_alone_cannot_issue(self, client):
        # 発行は GitHub ログイン済みの本人だけ（ユーザー名に紐づくトークンのため API キーでは不可）
        resp = client.post("/auth/mcp-token", headers={"X-API-KEY": "test-api-key-for-pytest"})
        assert resp.status_code == 401

    def test_mcp_token_cannot_issue_another_token(self, client):
        token, _ = create_mcp_token("alice")
        resp = client.post("/auth/mcp-token", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    def test_issues_token_bound_to_logged_in_user(self, client):
        headers = {"Authorization": f"Bearer {create_session_token('alice')}"}
        resp = client.post("/auth/mcp-token", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["username"] == "alice"
        assert verify_mcp_token(body["token"]) == "alice"
        assert body["expires_at"]
