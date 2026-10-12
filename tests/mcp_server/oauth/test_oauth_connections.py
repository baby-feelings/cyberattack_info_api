"""OAuth 接続の一覧・接続解除（`/auth/oauth-connections`）のテスト（Issue #303）。

認可〜トークン取得は test_oauth_flow のヘルパーで通し、本人確認のセッションは
`create_session_token` で作る。
"""
import os
from datetime import UTC, datetime, timedelta

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")
os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret-key-for-pytest")

from app.auth.session import create_session_token  # noqa: E402
from app.mcp_server.mcp_token import verify_mcp_token  # noqa: E402
from app.mcp_server.mcp_token_store import is_usable, issue_token  # noqa: E402
from app.mcp_server.models import OAuthRefreshToken  # noqa: E402
from tests.mcp_server.oauth.test_oauth_flow import (  # noqa: E402
    _full_flow,
    _register,
    _token_request,
)


def _auth(login: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_session_token(login)}"}


def _connections(http, login: str) -> list[dict]:
    """そのユーザーが見える OAuth 接続の一覧。"""
    res = http.get("/auth/oauth-connections", headers=_auth(login))
    assert res.status_code == 200
    return res.json()["connections"]


def _connect(http, login: str, name: str = "Claude Code") -> tuple[str, dict]:
    """そのユーザーが OAuth でクライアントを接続した状態にし、(client_id, トークン応答) を返す。"""
    client_id, code, verifier = _full_flow(http, login=login, name=name)
    res = _token_request(http, client_id, code, verifier)
    assert res.status_code == 200, res.text
    return client_id, res.json()


class TestList:
    def test_lists_own_connection_with_client_name(self, http):
        client_id, _ = _connect(http, "alice", name="Claude Code")
        res = http.get("/auth/oauth-connections", headers=_auth("alice"))
        assert res.status_code == 200
        [conn] = res.json()["connections"]
        assert conn["client_id"] == client_id and conn["client_name"] == "Claude Code"
        assert conn["connected_at"] and conn["expires_at"]

    def test_does_not_list_other_users_connections(self, http):
        _connect(http, "alice")
        res = http.get("/auth/oauth-connections", headers=_auth("mallory"))
        assert res.json()["connections"] == []

    def test_requires_login(self, http):
        assert http.get("/auth/oauth-connections").status_code == 401

    def test_excludes_revoked_and_expired(self, http, db_session):
        _connect(http, "alice")
        row = db_session.query(OAuthRefreshToken).one()
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db_session.commit()
        assert _connections(http, "alice") == []

    def test_rotation_keeps_a_single_entry(self, http):
        client_id, first = _connect(http, "alice")
        http.post("/token", data={
            "grant_type": "refresh_token", "client_id": client_id,
            "refresh_token": first["refresh_token"],
        })
        conns = _connections(http, "alice")
        assert len(conns) == 1  # 使用済み（ローテーション前）のトークンは数えない

    def test_name_is_returned_as_data_not_markup(self, http):
        _connect(http, "alice", name="<img src=x onerror=alert(1)>")
        [conn] = _connections(http, "alice")
        assert conn["client_name"] == "<img src=x onerror=alert(1)>"  # エスケープは表示側（React）


class TestDisconnect:
    def test_disconnect_revokes_refresh_and_access_tokens(self, http, db_session):
        client_id, first = _connect(http, "alice")
        res = http.delete(f"/auth/oauth-connections/{client_id}", headers=_auth("alice"))
        assert res.status_code == 200 and res.json()["disconnected"] is True
        # リフレッシュトークンは使えない
        again = http.post("/token", data={
            "grant_type": "refresh_token", "client_id": client_id,
            "refresh_token": first["refresh_token"],
        })
        assert again.status_code == 400
        # 発行済みのアクセストークンも使えない
        claims = verify_mcp_token(first["access_token"])
        db_session.expire_all()
        assert not is_usable(db_session, claims)
        # 一覧からも消える
        assert _connections(http, "alice") == []

    def test_cannot_disconnect_other_users_connection(self, http, db_session):
        client_id, first = _connect(http, "alice")
        res = http.delete(f"/auth/oauth-connections/{client_id}", headers=_auth("mallory"))
        assert res.status_code == 404  # 存在を推測させない
        # alice の接続は無傷
        ok = http.post("/token", data={
            "grant_type": "refresh_token", "client_id": client_id,
            "refresh_token": first["refresh_token"],
        })
        assert ok.status_code == 200

    def test_unknown_client_is_404(self, http):
        res = http.delete("/auth/oauth-connections/nope", headers=_auth("alice"))
        assert res.status_code == 404

    def test_requires_login(self, http):
        assert http.delete("/auth/oauth-connections/x").status_code == 401

    def test_does_not_touch_manually_issued_tokens(self, http, db_session):
        manual, _ = issue_token(db_session, "alice", 30)
        client_id, _ = _connect(http, "alice")
        http.delete(f"/auth/oauth-connections/{client_id}", headers=_auth("alice"))
        claims = verify_mcp_token(manual)
        db_session.expire_all()
        assert is_usable(db_session, claims)

    def test_only_the_target_client_is_disconnected(self, http):
        a, first_a = _connect(http, "alice", name="A")
        b = _register(http, name="B")
        http.delete(f"/auth/oauth-connections/{b}", headers=_auth("alice"))  # B は未接続: 404
        conns = _connections(http, "alice")
        assert [c["client_id"] for c in conns] == [a]
