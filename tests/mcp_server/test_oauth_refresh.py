"""OAuth 2.1 のリフレッシュトークンのローテーション・盗用検知と /revoke のテスト（PR3、#303）。

認可〜最初のトークン取得は test_oauth_flow のヘルパーで通し、GitHub 通信だけモックする。
"""
import os
from datetime import UTC, datetime, timedelta

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")
os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret-key-for-pytest")

from app.mcp_server import oauth_refresh  # noqa: E402
from app.mcp_server.mcp_token import verify_mcp_token  # noqa: E402
from app.mcp_server.mcp_token_store import is_usable  # noqa: E402
from app.mcp_server.models import McpToken, OAuthRefreshToken  # noqa: E402
from tests.mcp_server.test_oauth_flow import (  # noqa: E402
    _full_flow,
    _register,
    _token_request,
)


def _first_tokens(http, login="alice") -> tuple[str, dict]:
    """認可フローを通し、(client_id, 最初のトークン応答) を返す。"""
    client_id, code, verifier = _full_flow(http, login=login)
    res = _token_request(http, client_id, code, verifier)
    assert res.status_code == 200, res.text
    return client_id, res.json()


def _refresh(http, client_id: str, refresh_token: str, **extra):
    return http.post("/token", data={
        "grant_type": "refresh_token", "client_id": client_id,
        "refresh_token": refresh_token, **extra,
    })


def _revoke(http, client_id: str, token: str, hint: str | None = None):
    # SDK の失効リクエストは client_secret のキーを必須とする（公開クライアントは空）
    data = {"token": token, "client_id": client_id, "client_secret": ""}
    if hint:
        data["token_type_hint"] = hint
    return http.post("/revoke", data=data)


class TestIssue:
    def test_first_exchange_returns_a_refresh_token_stored_only_as_a_hash(self, http, db_session):
        _, body = _first_tokens(http)
        refresh = body["refresh_token"]
        assert refresh
        row = db_session.query(OAuthRefreshToken).one()
        assert row.token_hash == oauth_refresh.hash_token(refresh)
        assert refresh not in (row.token_hash, row.family_id)  # 平文は保存しない
        assert row.username == "alice" and row.scope == "mcp:read"


class TestRotation:
    def test_refresh_returns_new_working_tokens(self, http, db_session):
        client_id, first = _first_tokens(http)
        res = _refresh(http, client_id, first["refresh_token"])
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["refresh_token"] != first["refresh_token"]  # ローテーションする
        assert body["access_token"] != first["access_token"]
        claims = verify_mcp_token(body["access_token"])
        assert claims is not None and claims.username == "alice"
        db_session.expire_all()
        assert is_usable(db_session, claims)

    def test_chain_can_continue(self, http):
        client_id, first = _first_tokens(http)
        second = _refresh(http, client_id, first["refresh_token"]).json()
        third = _refresh(http, client_id, second["refresh_token"])
        assert third.status_code == 200

    def test_reusing_a_rotated_token_revokes_the_whole_family(self, http, db_session):
        """盗用の疑い: 使用済みのトークンの再提示で、系統の全トークンが使えなくなる。"""
        client_id, first = _first_tokens(http)
        second = _refresh(http, client_id, first["refresh_token"]).json()
        # 古い（使用済みの）トークンを再提示 → 拒否
        replay = _refresh(http, client_id, first["refresh_token"])
        assert replay.status_code == 400 and replay.json()["error"] == "invalid_grant"
        # 正規の最新のトークンも失効している（再認可が必要）
        latest = _refresh(http, client_id, second["refresh_token"])
        assert latest.status_code == 400
        db_session.expire_all()
        assert all(r.revoked_at is not None for r in db_session.query(OAuthRefreshToken))

    def test_rotate_succeeds_only_once(self, http, db_session):
        """同じトークンを同時に2回交換しようとしても、成功するのは片方だけ。"""
        client_id, first = _first_tokens(http)
        row = db_session.query(OAuthRefreshToken).one()
        assert oauth_refresh.rotate(db_session, row) is True
        assert oauth_refresh.rotate(db_session, row) is False

    def test_other_client_cannot_use_the_token(self, http):
        client_id, first = _first_tokens(http)
        other = _register(http, name="other")
        res = _refresh(http, other, first["refresh_token"])
        assert res.status_code == 400 and res.json()["error"] == "invalid_grant"

    def test_expired_token_is_rejected(self, http, db_session):
        client_id, first = _first_tokens(http)
        row = db_session.query(OAuthRefreshToken).one()
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db_session.commit()
        assert _refresh(http, client_id, first["refresh_token"]).status_code == 400

    def test_unknown_token_is_rejected(self, http):
        client_id = _register(http)
        assert _refresh(http, client_id, "nope").status_code == 400

    def test_scope_cannot_be_widened(self, http):
        client_id, first = _first_tokens(http)
        res = _refresh(http, client_id, first["refresh_token"], scope="mcp:read admin")
        assert res.status_code == 400 and res.json()["error"] == "invalid_scope"

    def test_same_scope_is_allowed(self, http):
        client_id, first = _first_tokens(http)
        res = _refresh(http, client_id, first["refresh_token"], scope="mcp:read")
        assert res.status_code == 200 and res.json()["scope"] == "mcp:read"

    def test_stale_rows_are_purged_when_issuing(self, http, db_session):
        client_id, first = _first_tokens(http)
        old = db_session.query(OAuthRefreshToken).one()
        old.expires_at = datetime.now(UTC) - timedelta(days=60)  # 保持期間（7日）を大きく過ぎた
        db_session.commit()
        old_hash = old.token_hash
        oauth_refresh.issue(db_session, client_id, "alice", "mcp:read", None)
        assert db_session.get(OAuthRefreshToken, old_hash) is None


class TestRevoke:
    def test_revoking_the_refresh_token_cancels_all_grants_for_the_client(self, http, db_session):
        client_id, first = _first_tokens(http)
        assert _revoke(http, client_id, first["refresh_token"], "refresh_token").status_code == 200
        # リフレッシュトークンは使えない
        assert _refresh(http, client_id, first["refresh_token"]).status_code == 400
        # 発行済みのアクセストークンも使えない
        claims = verify_mcp_token(first["access_token"])
        db_session.expire_all()
        assert not is_usable(db_session, claims)

    def test_revoking_only_the_access_token_keeps_the_refresh_token(self, http, db_session):
        client_id, first = _first_tokens(http)
        assert _revoke(http, client_id, first["access_token"], "access_token").status_code == 200
        claims = verify_mcp_token(first["access_token"])
        db_session.expire_all()
        assert not is_usable(db_session, claims)
        assert _refresh(http, client_id, first["refresh_token"]).status_code == 200

    def test_unknown_token_returns_200_per_rfc(self, http):
        client_id = _register(http)
        assert _revoke(http, client_id, "nope").status_code == 200

    def test_another_client_cannot_revoke_the_token(self, http, db_session):
        client_id, first = _first_tokens(http)
        other = _register(http, name="other")
        assert _revoke(http, other, first["refresh_token"]).status_code == 200  # 何も起きない
        assert _refresh(http, client_id, first["refresh_token"]).status_code == 200

    def test_does_not_touch_manually_issued_tokens(self, http, db_session):
        from app.mcp_server.mcp_token_store import issue_token
        manual, _ = issue_token(db_session, "alice", 30)
        client_id, first = _first_tokens(http)
        _revoke(http, client_id, first["refresh_token"])
        claims = verify_mcp_token(manual)
        db_session.expire_all()
        assert is_usable(db_session, claims)  # 手動発行のトークンは生きている
        assert db_session.query(McpToken).filter(McpToken.oauth_client_id.is_(None)).count() == 1
