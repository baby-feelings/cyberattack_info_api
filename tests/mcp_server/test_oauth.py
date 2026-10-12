"""OAuth 2.1 認可サーバー（PR1: 動的クライアント登録・メタデータ）のテスト（Issue #303）。"""
import asyncio
import os
from datetime import UTC, datetime, timedelta

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")
os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret-key-for-pytest")

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from mcp.server.auth.provider import RegistrationError, TokenError  # noqa: E402
from mcp.shared.auth import OAuthClientInformationFull  # noqa: E402

from app.auth.models import OAuthClient  # noqa: E402
from app.mcp_server import oauth_clients  # noqa: E402
from app.mcp_server.oauth_provider import McpOAuthProvider  # noqa: E402
from app.mcp_server.oauth_routes import mount_oauth_routes  # noqa: E402
from tests.conftest import TestSessionLocal  # noqa: E402

ISSUER = "https://api.example.test"


def _client(client_id="c1", uris=("https://app.example.test/cb",)) -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id=client_id, redirect_uris=list(uris), client_name="t",
    )


@pytest.fixture(autouse=True)
def _clean(db_session):
    yield
    db_session.query(OAuthClient).delete()
    db_session.commit()


@pytest.fixture
def http() -> TestClient:
    """OAuth を有効にした最小の FastAPI アプリ（DB はテスト用）。"""
    app = FastAPI()
    from app.mcp_server import oauth_routes

    original = oauth_routes.SessionLocal
    oauth_routes.SessionLocal = TestSessionLocal
    try:
        assert mount_oauth_routes(app, issuer=ISSUER)
        yield TestClient(app, base_url=ISSUER)
    finally:
        oauth_routes.SessionLocal = original


class TestRedirectUriValidation:
    @pytest.mark.parametrize("uri", [
        "https://app.example.test/cb", "http://localhost:8080/cb",
        "http://127.0.0.1/cb", "http://[::1]:9/cb",
    ])
    def test_allowed(self, uri):
        oauth_clients.validate_redirect_uri(uri)

    @pytest.mark.parametrize("uri", [
        "http://evil.example/cb", "javascript:alert(1)", "data:text/html,x",
        "myapp://cb", "https://app.example.test/cb#frag", "https:///cb",
    ])
    def test_rejected(self, uri):
        with pytest.raises(RegistrationError):
            oauth_clients.validate_redirect_uri(uri)

    def test_too_many_uris_rejected(self):
        uris = [f"https://a{i}.example.test/cb" for i in range(oauth_clients.MAX_REDIRECT_URIS + 1)]
        with pytest.raises(RegistrationError):
            oauth_clients.validate_registration(_client(uris=uris))


class TestClientStore:
    def test_save_and_load_roundtrip(self, db_session):
        oauth_clients.save_client(db_session, _client("abc"))
        loaded = oauth_clients.load_client(db_session, "abc")
        assert loaded is not None and loaded.client_name == "t"

    def test_unknown_client_is_none(self, db_session):
        assert oauth_clients.load_client(db_session, "nope") is None

    def test_hourly_limit(self, db_session, monkeypatch):
        monkeypatch.setattr(oauth_clients, "MAX_REGISTRATIONS_PER_HOUR", 2)
        oauth_clients.save_client(db_session, _client("a"))
        oauth_clients.save_client(db_session, _client("b"))
        with pytest.raises(RegistrationError):
            oauth_clients.save_client(db_session, _client("c"))

    def test_total_limit(self, db_session, monkeypatch):
        monkeypatch.setattr(oauth_clients, "MAX_CLIENTS", 1)
        oauth_clients.save_client(db_session, _client("a"))
        with pytest.raises(RegistrationError):
            oauth_clients.save_client(db_session, _client("b"))

    def test_unused_old_clients_purged_but_used_kept(self, db_session):
        old = datetime.now(UTC) - timedelta(days=40)
        oauth_clients.save_client(db_session, _client("unused"), now=old)
        oauth_clients.save_client(db_session, _client("used"), now=old)
        oauth_clients.touch_client(db_session, "used")
        assert oauth_clients.purge_unused_clients(db_session) == 1
        assert oauth_clients.load_client(db_session, "unused") is None
        assert oauth_clients.load_client(db_session, "used") is not None


class TestProvider:
    def test_register_and_get(self):
        provider = McpOAuthProvider(TestSessionLocal, ISSUER)

        async def scenario():
            await provider.register_client(_client("p1"))
            assert (await provider.get_client("p1")) is not None
            assert (await provider.get_client("zzz")) is None

        asyncio.run(scenario())

    def test_refresh_not_supported_yet(self):
        provider = McpOAuthProvider(TestSessionLocal, ISSUER)
        c = _client()

        async def scenario():
            with pytest.raises(TokenError):
                await provider.exchange_refresh_token(c, None, [])  # type: ignore[arg-type]
            assert await provider.load_refresh_token(c, "x") is None
            assert await provider.load_access_token("x") is None
            assert await provider.revoke_token(None) is None  # type: ignore[arg-type]

        asyncio.run(scenario())


class TestRoutes:
    def test_disabled_without_issuer(self):
        app = FastAPI()
        before = len(app.router.routes)  # FastAPI 既定のルート（/docs 等）
        assert mount_oauth_routes(app, issuer="") is False
        assert len(app.router.routes) == before

    def test_metadata(self, http):
        body = http.get("/.well-known/oauth-authorization-server").json()
        assert body["issuer"].rstrip("/") == ISSUER
        assert body["code_challenge_methods_supported"] == ["S256"]
        assert body["registration_endpoint"].endswith("/register")

    def test_protected_resource_metadata(self, http):
        body = http.get("/.well-known/oauth-protected-resource/mcp").json()
        assert body["resource"] == f"{ISSUER}/mcp"
        assert body["scopes_supported"] == ["mcp:read"]

    def test_register_ok_and_persisted(self, http, db_session):
        res = http.post("/register", json={
            "redirect_uris": ["http://localhost:33418/callback"], "client_name": "Claude Code",
            "token_endpoint_auth_method": "none",
        })
        assert res.status_code == 201
        client_id = res.json()["client_id"]
        assert oauth_clients.load_client(db_session, client_id) is not None

    def test_register_rejects_bad_redirect(self, http):
        res = http.post("/register", json={"redirect_uris": ["http://evil.example/cb"]})
        assert res.status_code == 400
        assert res.json()["error"] == "invalid_redirect_uri"

    def test_register_rejects_foreign_scope(self, http):
        res = http.post("/register", json={
            "redirect_uris": ["https://app.example.test/cb"], "scope": "admin",
        })
        assert res.status_code == 400
