"""app.mcp_server.oauth_services（認可・交換・リフレッシュ・失効の判断）の単体テスト。

HTTP や async を介さず、`Session` を直接渡して判断だけを検証する（通しの流れは test_oauth_flow）。
"""
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")
os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret-key-for-pytest")

import pytest  # noqa: E402
from mcp.server.auth.provider import (  # noqa: E402
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull  # noqa: E402
from pydantic import AnyUrl  # noqa: E402

from app.mcp_server import oauth_clients, oauth_refresh  # noqa: E402
from app.mcp_server.mcp_token import verify_mcp_token  # noqa: E402
from app.mcp_server.mcp_token_store import is_usable, issue_token  # noqa: E402
from app.mcp_server.oauth_services import (  # noqa: E402
    SCOPE,
    AccessTokenService,
    AuthorizationService,
    RefreshService,
)

ISSUER = "https://api.example.test"
_REDIRECT = "http://localhost:9999/callback"


def _client(db) -> OAuthClientInformationFull:
    client = OAuthClientInformationFull(
        client_id="client-1", redirect_uris=[AnyUrl(_REDIRECT)],
        token_endpoint_auth_method="none",
    )
    oauth_clients.save_client(db, client)
    return client


def _params(**kw) -> AuthorizationParams:
    base = {
        "state": "s", "scopes": None, "code_challenge": "c" * 43,
        "redirect_uri": AnyUrl(_REDIRECT), "redirect_uri_provided_explicitly": True,
        "resource": None,
    }
    base.update(kw)
    return AuthorizationParams(**base)


class TestAuthorizationServiceBegin:
    def test_returns_the_consent_url_for_a_valid_request(self, db_session):
        client = _client(db_session)
        url = AuthorizationService(ISSUER).begin(db_session, client, _params())
        assert url.startswith(f"{ISSUER}/oauth/consent?request_id=")

    def test_rejects_scopes_other_than_the_read_scope(self, db_session):
        client = _client(db_session)
        with pytest.raises(AuthorizeError) as exc:
            AuthorizationService(ISSUER).begin(db_session, client, _params(scopes=["admin"]))
        assert exc.value.error == "invalid_scope"

    def test_rejects_an_unknown_resource(self, db_session):
        client = _client(db_session)
        with pytest.raises(AuthorizeError) as exc:
            AuthorizationService(ISSUER).begin(
                db_session, client, _params(resource="https://evil.example/mcp"),
            )
        assert exc.value.error == "invalid_request"

    def test_accepts_this_servers_own_resource(self, db_session):
        client = _client(db_session)
        url = AuthorizationService(ISSUER).begin(
            db_session, client, _params(resource=f"{ISSUER}/mcp"),
        )
        assert "request_id=" in url


class TestAuthorizationServiceCode:
    def test_unknown_code_is_none(self, db_session):
        assert AuthorizationService.load_code(db_session, "client-1", "nope") is None

    def test_exchange_rejects_a_code_without_a_subject(self, db_session):
        code = AuthorizationCode(
            code="x", scopes=[SCOPE], expires_at=9e9, client_id="client-1",
            code_challenge="c" * 43, redirect_uri=AnyUrl(_REDIRECT),
            redirect_uri_provided_explicitly=True, resource=None, subject=None,
        )
        with pytest.raises(TokenError) as exc:
            AuthorizationService.exchange(db_session, "client-1", code)
        assert exc.value.error == "invalid_grant"

    def test_exchange_rejects_a_code_that_was_never_issued(self, db_session):
        code = AuthorizationCode(
            code="never-issued", scopes=[SCOPE], expires_at=9e9, client_id="client-1",
            code_challenge="c" * 43, redirect_uri=AnyUrl(_REDIRECT),
            redirect_uri_provided_explicitly=True, resource=None, subject="alice",
        )
        with pytest.raises(TokenError):
            AuthorizationService.exchange(db_session, "client-1", code)


class TestRefreshService:
    def _issue(self, db, username="alice", client_id="client-1"):
        _client(db)
        return oauth_refresh.issue(db, client_id, username, SCOPE, None)

    def test_load_returns_the_token_for_its_own_client_only(self, db_session):
        raw = self._issue(db_session)
        assert RefreshService.load(db_session, "client-1", raw).subject == "alice"
        assert RefreshService.load(db_session, "other-client", raw) is None
        assert RefreshService.load(db_session, None, raw) is None

    def test_exchange_rotates_and_the_old_token_stops_working(self, db_session):
        raw = self._issue(db_session)
        token = RefreshService.load(db_session, "client-1", raw)
        issued = RefreshService.exchange(db_session, "client-1", token, [])
        assert issued.refresh_token != raw
        assert issued.scope == SCOPE
        assert verify_mcp_token(issued.access_token) is not None
        with pytest.raises(TokenError):
            RefreshService.exchange(db_session, "client-1", token, [])  # 使用済みの再提示

    def test_exchange_cannot_widen_the_scope(self, db_session):
        raw = self._issue(db_session)
        token = RefreshService.load(db_session, "client-1", raw)
        with pytest.raises(TokenError) as exc:
            RefreshService.exchange(db_session, "client-1", token, [SCOPE, "admin"])
        assert exc.value.error == "invalid_scope"

    def test_exchange_requires_a_subject(self, db_session):
        token = RefreshToken(
            token="t", client_id="client-1", scopes=[SCOPE], expires_at=9_999_999_999,
            resource=None, subject=None,
        )
        with pytest.raises(TokenError):
            RefreshService.exchange(db_session, "client-1", token, [])

    def test_revoke_all_invalidates_refresh_tokens_and_access_tokens(self, db_session):
        raw = self._issue(db_session)
        token = RefreshService.load(db_session, "client-1", raw)
        issued = RefreshService.exchange(db_session, "client-1", token, [])
        RefreshService.revoke_all(db_session, "alice", "client-1")

        assert RefreshService.load(db_session, "client-1", issued.refresh_token) is None
        claims = verify_mcp_token(issued.access_token)
        db_session.expire_all()
        assert not is_usable(db_session, claims)


class TestAccessTokenService:
    def _oauth_access_token(self, db):
        raw = oauth_refresh.issue(db, _client(db).client_id, "alice", SCOPE, None)
        token = RefreshService.load(db, "client-1", raw)
        return RefreshService.exchange(db, "client-1", token, []).access_token

    def test_load_returns_oauth_issued_tokens(self, db_session):
        access = AccessTokenService.load(db_session, self._oauth_access_token(db_session))
        assert access is not None
        assert (access.subject, access.client_id, access.scopes) == ("alice", "client-1", [SCOPE])

    def test_load_ignores_manually_issued_tokens(self, db_session):
        manual, _row = issue_token(db_session, "alice", 30)
        assert AccessTokenService.load(db_session, manual) is None

    def test_load_rejects_garbage(self, db_session):
        assert AccessTokenService.load(db_session, "not-a-jwt") is None

    def test_revoke_only_works_for_the_owner(self, db_session):
        raw = self._oauth_access_token(db_session)
        AccessTokenService.revoke(db_session, "mallory", raw)  # 他人: 何も起きない
        assert AccessTokenService.load(db_session, raw) is not None
        AccessTokenService.revoke(db_session, "alice", raw)
        assert AccessTokenService.load(db_session, raw) is None

    def test_revoke_is_idempotent(self, db_session):
        raw = self._oauth_access_token(db_session)
        AccessTokenService.revoke(db_session, "alice", raw)
        AccessTokenService.revoke(db_session, "alice", raw)  # 失効済みでも例外にならない
        assert AccessTokenService.load(db_session, raw) is None

