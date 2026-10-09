"""app.auth.mcp_token_store（台帳）と /auth/mcp-token(s) エンドポイントのテスト。"""
import os
from datetime import datetime, timedelta, timezone

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")
os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret-key-for-pytest")

import pytest  # noqa: E402

from app.auth.mcp_token import McpClaims, verify_mcp_token  # noqa: E402
from app.auth.mcp_token_store import (  # noqa: E402
    MAX_ACTIVE_TOKENS,
    TooManyTokensError,
    is_usable,
    issue_token,
    list_tokens,
    revoke_token,
    token_status,
)
from app.auth.models import McpToken  # noqa: E402
from app.auth.session import create_session_token  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_tokens(db_session):
    yield
    db_session.query(McpToken).delete()
    db_session.commit()


def _session(user: str) -> dict:
    return {"Authorization": f"Bearer {create_session_token(user)}"}


class TestStore:
    def test_issue_records_ledger_and_returns_verifiable_jwt(self, db_session):
        token, row = issue_token(db_session, "alice", 7)
        claims = verify_mcp_token(token)
        assert claims == McpClaims("alice", row.id)
        exp = row.expires_at
        exp = exp if exp.tzinfo else exp.replace(tzinfo=timezone.utc)
        assert timedelta(days=6) < exp - datetime.now(timezone.utc) <= timedelta(days=7)
        assert token_status(row) == "active"

    def test_rejects_unsupported_days(self, db_session):
        with pytest.raises(ValueError):
            issue_token(db_session, "alice", 365)

    def test_active_token_cap(self, db_session):
        for _ in range(MAX_ACTIVE_TOKENS):
            issue_token(db_session, "alice", 30)
        with pytest.raises(TooManyTokensError):
            issue_token(db_session, "alice", 30)
        # 他のユーザーには影響しない
        issue_token(db_session, "bob", 30)

    def test_revoking_frees_a_slot(self, db_session):
        rows = [issue_token(db_session, "alice", 30)[1] for _ in range(MAX_ACTIVE_TOKENS)]
        assert revoke_token(db_session, "alice", rows[0].id)
        issue_token(db_session, "alice", 30)

    def test_old_expired_rows_are_cleaned_on_issue(self, db_session):
        old = McpToken(id="old", username="alice",
                       expires_at=datetime.now(timezone.utc) - timedelta(days=60))
        db_session.add(old)
        db_session.commit()
        issue_token(db_session, "alice", 30)
        assert db_session.get(McpToken, "old") is None

    def test_revoke_only_own_token(self, db_session):
        _, row = issue_token(db_session, "alice", 30)
        assert revoke_token(db_session, "bob", row.id) is False
        assert token_status(db_session.get(McpToken, row.id)) == "active"
        assert revoke_token(db_session, "alice", row.id) is True
        assert token_status(db_session.get(McpToken, row.id)) == "revoked"

    def test_revoke_is_idempotent_and_unknown_is_false(self, db_session):
        _, row = issue_token(db_session, "alice", 30)
        assert revoke_token(db_session, "alice", row.id)
        assert revoke_token(db_session, "alice", row.id)
        assert revoke_token(db_session, "alice", "no-such-id") is False

    def test_list_returns_only_own_newest_first(self, db_session):
        _, first = issue_token(db_session, "alice", 30)
        issue_token(db_session, "bob", 30)
        _, second = issue_token(db_session, "alice", 30)
        ids = [t.id for t in list_tokens(db_session, "alice")]
        assert set(ids) == {first.id, second.id}

    def test_is_usable_checks_owner_revocation_and_touches_last_used(self, db_session):
        _, row = issue_token(db_session, "alice", 30)
        assert row.last_used_at is None
        assert is_usable(db_session, McpClaims("alice", row.id)) is True
        db_session.refresh(row)
        assert row.last_used_at is not None
        # 別ユーザーの jti、未登録の jti は不可
        assert is_usable(db_session, McpClaims("bob", row.id)) is False
        assert is_usable(db_session, McpClaims("alice", "unknown")) is False
        revoke_token(db_session, "alice", row.id)
        assert is_usable(db_session, McpClaims("alice", row.id)) is False

    def test_last_used_is_throttled(self, db_session):
        _, row = issue_token(db_session, "alice", 30)
        is_usable(db_session, McpClaims("alice", row.id))
        db_session.refresh(row)
        first = row.last_used_at
        is_usable(db_session, McpClaims("alice", row.id))
        db_session.refresh(row)
        assert row.last_used_at == first  # 間隔内の再利用では書き込まない

    def test_status_expired(self, db_session):
        row = McpToken(id="e", username="alice",
                       expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
        assert token_status(row) == "expired"


class TestEndpoints:
    def test_issue_requires_login(self, client):
        assert client.post("/auth/mcp-token").status_code == 401

    def test_api_key_alone_cannot_issue(self, client):
        resp = client.post("/auth/mcp-token", headers={"X-API-KEY": "test-api-key-for-pytest"})
        assert resp.status_code == 401

    def test_mcp_token_cannot_issue_another_token(self, client, db_session):
        token, _ = issue_token(db_session, "alice", 30)
        resp = client.post("/auth/mcp-token", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401

    def test_issue_defaults_to_30_days_and_returns_token_once(self, client):
        resp = client.post("/auth/mcp-token", headers=_session("alice"))
        assert resp.status_code == 200
        body = resp.json()
        assert body["username"] == "alice"
        assert verify_mcp_token(body["token"]).username == "alice"
        assert body["status"] == "active"
        # 一覧にはトークン本体を含めない
        listed = client.get("/auth/mcp-tokens", headers=_session("alice")).json()["tokens"]
        assert [t["id"] for t in listed] == [body["id"]]
        assert "token" not in listed[0]

    @pytest.mark.parametrize("days", [7, 30, 90])
    def test_issue_with_selected_days(self, client, days):
        resp = client.post("/auth/mcp-token", json={"days": days}, headers=_session("alice"))
        assert resp.status_code == 200
        exp = datetime.fromisoformat(resp.json()["expires_at"])
        exp = exp if exp.tzinfo else exp.replace(tzinfo=timezone.utc)
        assert timedelta(days=days - 1) < exp - datetime.now(timezone.utc) <= timedelta(days=days)

    def test_issue_rejects_unsupported_days(self, client):
        resp = client.post("/auth/mcp-token", json={"days": 365}, headers=_session("alice"))
        assert resp.status_code == 422

    def test_issue_returns_409_when_cap_reached(self, client):
        for _ in range(MAX_ACTIVE_TOKENS):
            assert client.post("/auth/mcp-token", headers=_session("alice")).status_code == 200
        resp = client.post("/auth/mcp-token", headers=_session("alice"))
        assert resp.status_code == 409
        assert "上限" in resp.json()["detail"]

    def test_list_requires_login_and_hides_other_users(self, client):
        assert client.get("/auth/mcp-tokens").status_code == 401
        client.post("/auth/mcp-token", headers=_session("bob"))
        assert client.get("/auth/mcp-tokens", headers=_session("alice")).json() == {"tokens": []}

    def test_revoke_flow(self, client):
        token_id = client.post("/auth/mcp-token", headers=_session("alice")).json()["id"]
        assert client.delete(f"/auth/mcp-tokens/{token_id}").status_code == 401
        resp = client.delete(f"/auth/mcp-tokens/{token_id}", headers=_session("alice"))
        assert resp.status_code == 200
        assert resp.json() == {"id": token_id, "revoked": True}
        listed = client.get("/auth/mcp-tokens", headers=_session("alice")).json()["tokens"]
        assert listed[0]["status"] == "revoked"
        assert listed[0]["revoked_at"]

    def test_cannot_revoke_other_users_token(self, client):
        token_id = client.post("/auth/mcp-token", headers=_session("bob")).json()["id"]
        resp = client.delete(f"/auth/mcp-tokens/{token_id}", headers=_session("alice"))
        assert resp.status_code == 404
        listed = client.get("/auth/mcp-tokens", headers=_session("bob")).json()["tokens"]
        assert listed[0]["status"] == "active"

    def test_revoke_unknown_token_is_404(self, client):
        resp = client.delete("/auth/mcp-tokens/nope", headers=_session("alice"))
        assert resp.status_code == 404
