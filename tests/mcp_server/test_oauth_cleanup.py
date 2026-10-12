"""使われない OAuth 接続・登録の自動整理（oauth_cleanup）のテスト（Issue #303）。"""
import os
from datetime import UTC, datetime, timedelta

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")
os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret-key-for-pytest")

from app.mcp_server import oauth_cleanup, oauth_connections  # noqa: E402
from app.mcp_server.mcp_token import verify_mcp_token  # noqa: E402
from app.mcp_server.mcp_token_store import is_usable  # noqa: E402
from app.mcp_server.models import McpToken, OAuthClient  # noqa: E402
from app.mcp_server.oauth_cleanup import (  # noqa: E402
    UNUSED_CONNECTION_TTL,
    disconnect_unused_connections,
    run_oauth_cleanup,
)
from tests.conftest import TestSessionLocal  # noqa: E402
from tests.mcp_server.test_oauth_connections import _connect, _connections  # noqa: E402


def _later(days: float) -> datetime:
    return datetime.now(UTC) + timedelta(days=days)


class TestDisconnectUnusedConnections:
    def test_disconnects_a_connection_never_used_past_the_ttl(self, http, db_session):
        _connect(http, "alice")
        now = _later(UNUSED_CONNECTION_TTL.days + 1)
        assert disconnect_unused_connections(db_session, now) == 1
        assert _connections(http, "alice") == []

    def test_keeps_a_recent_unused_connection(self, http, db_session):
        _connect(http, "alice")
        assert disconnect_unused_connections(db_session, _later(1)) == 0
        assert len(_connections(http, "alice")) == 1

    def test_keeps_a_connection_that_was_used(self, http, db_session):
        _, tokens = _connect(http, "alice")
        claims = verify_mcp_token(tokens["access_token"])
        assert is_usable(db_session, claims)  # /mcp で使われると last_used_at が付く
        db_session.expire_all()
        assert disconnect_unused_connections(db_session, _later(10)) == 0
        assert len(_connections(http, "alice")) == 1

    def test_revoked_access_token_of_a_disconnected_client_is_unusable(self, http, db_session):
        _, tokens = _connect(http, "alice")
        disconnect_unused_connections(db_session, _later(10))
        claims = verify_mcp_token(tokens["access_token"])
        db_session.expire_all()
        assert not is_usable(db_session, claims)

    def test_only_unused_clients_are_disconnected_per_user(self, http, db_session):
        used_client, used_tokens = _connect(http, "alice", name="used")
        unused_client, _ = _connect(http, "alice", name="unused")
        other_client, _ = _connect(http, "bob", name="bob's unused")
        assert is_usable(db_session, verify_mcp_token(used_tokens["access_token"]))
        db_session.expire_all()

        assert disconnect_unused_connections(db_session, _later(10)) == 2  # alice の未使用と bob
        assert [c["client_id"] for c in _connections(http, "alice")] == [used_client]
        assert _connections(http, "bob") == []
        assert unused_client != other_client

    def test_does_not_touch_manually_issued_tokens(self, http, db_session):
        from app.mcp_server.mcp_token_store import issue_token

        manual, _ = issue_token(db_session, "alice", 30)
        _connect(http, "alice")
        disconnect_unused_connections(db_session, _later(10))
        db_session.expire_all()
        assert is_usable(db_session, verify_mcp_token(manual))

    def test_second_run_is_a_noop(self, http, db_session):
        _connect(http, "alice")
        now = _later(10)
        assert disconnect_unused_connections(db_session, now) == 1
        assert disconnect_unused_connections(db_session, now) == 0


class TestRunOauthCleanup:
    def test_runs_disconnect_and_purges_unused_clients(self, http, db_session, monkeypatch):
        _connect(http, "alice")
        stale = OAuthClient(
            client_id="stale", client_info_json="{}",
            created_at=_later(-(oauth_cleanup.oauth_clients.UNUSED_RETENTION.days + 1)),
        )
        db_session.add(stale)
        db_session.commit()
        monkeypatch.setattr(
            oauth_cleanup, "disconnect_unused_connections",
            lambda db, now=None: disconnect_unused_connections(db, _later(10)),
        )

        run_oauth_cleanup(TestSessionLocal)

        db_session.expire_all()
        assert db_session.get(OAuthClient, "stale") is None  # 未使用の登録は削除
        assert _connections(http, "alice") == []  # 未使用の接続は解除
        assert db_session.query(McpToken).filter(McpToken.revoked_at.is_(None)).count() == 0

    def test_failure_does_not_propagate(self):
        def broken_factory():
            raise RuntimeError("db down")

        run_oauth_cleanup(broken_factory)  # 例外を外へ出さない（スケジューラを止めない）


def test_list_connections_uses_same_cutoff_basis(http, db_session):
    """一覧の connected_at（初回の許可日時）が、整理の判定基準と同じものであること。"""
    _connect(http, "alice")
    [conn] = oauth_connections.list_connections(db_session, "alice")
    assert datetime.fromisoformat(conn["connected_at"]) <= datetime.now(UTC)
