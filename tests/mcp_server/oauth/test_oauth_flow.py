"""OAuth 2.1 認可フロー（PR2: /authorize → 同意 → GitHub ログイン → 認可コード → /token）のテスト。

GitHub への通信（コード交換・ユーザー取得）だけをモックし、それ以外（SDK のルート・PKCE 検証・
DB・台帳・既存の /auth/github/callback）は実物で通す（Issue #303）。
"""
import base64
import hashlib
import os
import secrets
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")
os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret-key-for-pytest")

from fastapi.testclient import TestClient  # noqa: E402

from app.mcp_server.mcp_token import verify_mcp_token  # noqa: E402
from app.mcp_server.mcp_token_expiry import find_expiring_tokens  # noqa: E402
from app.mcp_server.mcp_token_store import is_usable, issue_token, list_tokens  # noqa: E402
from app.mcp_server.models import McpToken, OAuthAuthorization  # noqa: E402
from app.mcp_server.oauth import flow as oauth_flow  # noqa: E402
from tests.mcp_server.conftest import ISSUER  # noqa: E402

REDIRECT = "http://localhost:33418/callback"
_GH = "app.mcp_server.oauth.consent"


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _register(http, name="Claude Code", redirect=REDIRECT) -> str:
    res = http.post("/register", json={
        "redirect_uris": [redirect], "client_name": name, "token_endpoint_auth_method": "none",
    })
    assert res.status_code == 201, res.text
    return res.json()["client_id"]


def _authorize(http, client_id, challenge, state="st-1", redirect=REDIRECT, **extra):
    params = {
        "client_id": client_id, "response_type": "code", "redirect_uri": redirect,
        "code_challenge": challenge, "code_challenge_method": "S256", "state": state, **extra,
    }
    return http.get("/authorize", params=params)


def _request_id(location: str) -> str:
    return parse_qs(urlsplit(location).query)["request_id"][0]


def _open_consent(http, request_id: str):
    """同意画面を開く（このブラウザに認可リクエストが紐づき、Cookie が渡される）。"""
    page = http.get("/oauth/consent", params={"request_id": request_id})
    assert page.status_code == 200, page.text
    return page


def _github_state(http, request_id: str) -> str:
    """同意画面を開いて「許可」を押し、GitHub へ渡される state を取り出す。"""
    _open_consent(http, request_id)
    with patch(f"{_GH}.settings.GITHUB_OAUTH_CLIENT_ID", "gh-client"):
        res = http.post("/oauth/consent", content=f"request_id={request_id}&action=approve",
                        headers={"content-type": "application/x-www-form-urlencoded"})
    assert res.status_code == 303
    return parse_qs(urlsplit(res.headers["location"]).query)["state"][0]


def _callback(http, state: str, login="alice"):
    with patch("app.auth.github_router.settings.GITHUB_OAUTH_CLIENT_ID", "gh-client"), \
         patch("app.auth.github_router.settings.GITHUB_OAUTH_CLIENT_SECRET", "gh-secret"), \
         patch(f"{_GH}.settings.GITHUB_OAUTH_CLIENT_ID", "gh-client"), \
         patch(f"{_GH}.settings.GITHUB_OAUTH_CLIENT_SECRET", "gh-secret"), \
         patch(f"{_GH}.exchange_code_for_token", return_value="gho_dummy"), \
         patch(f"{_GH}.get_authenticated_user_login", return_value=login):
        return http.get("/auth/github/callback", params={"code": "gh-code", "state": state})


def _token_request(http, client_id, code, verifier, redirect=REDIRECT):
    return http.post("/token", data={
        "grant_type": "authorization_code", "client_id": client_id, "code": code,
        "code_verifier": verifier, "redirect_uri": redirect,
    })


def _full_flow(http, login="alice", name="Claude Code") -> tuple[str, str, str]:
    """認可〜コード取得までを通し、(client_id, code, verifier) を返す。"""
    verifier, challenge = _pkce()
    client_id = _register(http, name=name)
    loc = _authorize(http, client_id, challenge).headers["location"]
    state = _github_state(http, _request_id(loc))
    res = _callback(http, state, login)
    assert res.status_code == 302
    query = parse_qs(urlsplit(res.headers["location"]).query)
    assert query["state"] == ["st-1"]
    return client_id, query["code"][0], verifier


class TestHappyPath:
    def test_full_flow_issues_working_token(self, http, db_session):
        client_id, code, verifier = _full_flow(http, login="alice")
        res = _token_request(http, client_id, code, verifier)
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["token_type"] == "Bearer"
        assert body["expires_in"] == 3600
        assert body["scope"] == "mcp:read"

        # 発行されたトークンは、既存の MCP 認証（署名・期限・台帳）をそのまま通る
        claims = verify_mcp_token(body["access_token"])
        assert claims is not None and claims.username == "alice"
        db_session.expire_all()
        assert is_usable(db_session, claims)
        row = db_session.get(McpToken, claims.token_id)
        assert row.oauth_client_id == client_id

    def test_authorize_redirects_to_consent_with_request_id(self, http):
        _, challenge = _pkce()
        res = _authorize(http, _register(http), challenge)
        assert res.status_code == 302
        assert res.headers["location"].startswith(f"{ISSUER}/oauth/consent?request_id=")


class TestConsentPage:
    def test_shows_escaped_client_name_and_host(self, http):
        client_id = _register(http, name="<script>alert(1)</script>")
        _, challenge = _pkce()
        loc = _authorize(http, client_id, challenge).headers["location"]
        page = http.get("/oauth/consent", params={"request_id": _request_id(loc)})
        assert page.status_code == 200
        assert "<script>alert(1)</script>" not in page.text
        assert "&lt;script&gt;" in page.text
        assert "localhost:33418" in page.text
        assert page.headers["cache-control"] == "no-store"

    def test_csp_allows_only_the_pages_own_style_hash(self, http):
        import re
        page = http.get("/oauth/consent", params={"request_id": "nope"})  # エラーページにも付く
        csp = page.headers["content-security-policy"]
        style = re.search(r"<style>(.*?)</style>", page.text, re.S).group(1)
        digest = base64.b64encode(hashlib.sha256(style.encode()).digest()).decode()
        assert f"style-src 'sha256-{digest}'" in csp  # ページのスタイルと、許可したハッシュが一致
        assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp
        assert "unsafe-inline" not in csp and "script-src" not in csp  # スクリプトは一切許さない

    def test_unknown_request_id_is_rejected(self, http):
        assert http.get("/oauth/consent", params={"request_id": "nope"}).status_code == 400
        assert http.get("/oauth/consent").status_code == 400

    def test_deny_returns_access_denied_and_discards(self, http, db_session):
        _, challenge = _pkce()
        loc = _authorize(http, _register(http), challenge).headers["location"]
        rid = _request_id(loc)
        _open_consent(http, rid)
        res = http.post("/oauth/consent", content=f"request_id={rid}&action=deny",
                        headers={"content-type": "application/x-www-form-urlencoded"})
        query = parse_qs(urlsplit(res.headers["location"]).query)
        assert res.status_code == 302 and query["error"] == ["access_denied"]
        assert query["state"] == ["st-1"]
        assert db_session.get(OAuthAuthorization, rid) is None

    def test_unknown_action_and_oversized_body(self, http):
        _, challenge = _pkce()
        loc = _authorize(http, _register(http), challenge).headers["location"]
        rid = _request_id(loc)
        _open_consent(http, rid)
        bad = http.post("/oauth/consent", content=f"request_id={rid}&action=hack",
                        headers={"content-type": "application/x-www-form-urlencoded"})
        assert bad.status_code == 400
        big = http.post("/oauth/consent", content="x=" + "a" * 5000,
                        headers={"content-type": "application/x-www-form-urlencoded"})
        assert big.status_code == 413

    def test_github_login_requests_no_scope(self, http):
        _, challenge = _pkce()
        loc = _authorize(http, _register(http), challenge).headers["location"]
        _open_consent(http, _request_id(loc))
        with patch(f"{_GH}.settings.GITHUB_OAUTH_CLIENT_ID", "gh-client"):
            res = http.post("/oauth/consent",
                            content=f"request_id={_request_id(loc)}&action=approve",
                            headers={"content-type": "application/x-www-form-urlencoded"})
        query = parse_qs(urlsplit(res.headers["location"]).query)
        assert "scope" not in query  # 本人確認だけ。repo 権限は求めない

    def test_approve_without_github_config_is_503(self, http):
        _, challenge = _pkce()
        loc = _authorize(http, _register(http), challenge).headers["location"]
        _open_consent(http, _request_id(loc))
        with patch(f"{_GH}.settings.GITHUB_OAUTH_CLIENT_ID", ""):
            res = http.post("/oauth/consent",
                            content=f"request_id={_request_id(loc)}&action=approve",
                            headers={"content-type": "application/x-www-form-urlencoded"})
        assert res.status_code == 503


class TestBrowserBinding:
    """許可・拒否は、同意画面を最初に開いたブラウザだけが送れる（CSRF・URL の横取り対策）。"""

    def _pending(self, http) -> str:
        _, challenge = _pkce()
        return _request_id(_authorize(http, _register(http), challenge).headers["location"])

    def test_cookie_is_httponly_secure_lax_and_scoped(self, http):
        page = _open_consent(http, self._pending(http))
        cookie = page.headers["set-cookie"].lower()
        assert "mcp_oauth_consent=" in cookie
        assert "httponly" in cookie and "secure" in cookie
        # コールバック（/auth/github/callback）にも届くよう、パスは /
        assert "samesite=lax" in cookie and "path=/;" in cookie.replace("path=/ ", "path=/;")

    def test_post_without_opening_the_page_is_rejected(self, http, db_session):
        rid = self._pending(http)
        # 画面を開かず（Cookie なし）に直接 POST: CSRF の想定。承認されない
        res = http.post("/oauth/consent", content=f"request_id={rid}&action=approve",
                        headers={"content-type": "application/x-www-form-urlencoded"})
        assert res.status_code == 403
        assert db_session.get(OAuthAuthorization, rid) is not None  # 破棄もされない

    def test_other_browser_cannot_view_or_approve(self, http, db_session):
        rid = self._pending(http)
        _open_consent(http, rid)  # 正規のブラウザ（http）が先に開く
        attacker = TestClient(http.app, base_url=ISSUER, follow_redirects=False)  # Cookie なし
        assert attacker.get("/oauth/consent", params={"request_id": rid}).status_code == 403
        res = attacker.post("/oauth/consent", content=f"request_id={rid}&action=approve",
                            headers={"content-type": "application/x-www-form-urlencoded"})
        assert res.status_code == 403
        # 別のブラウザの Cookie を偽造しても通らない
        attacker.cookies.set("mcp_oauth_consent", "forged", domain="api.example.test", path="/")
        res = attacker.post("/oauth/consent", content=f"request_id={rid}&action=deny",
                            headers={"content-type": "application/x-www-form-urlencoded"})
        assert res.status_code == 403
        assert db_session.get(OAuthAuthorization, rid) is not None

    def test_github_callback_from_another_browser_is_rejected(self, http, db_session):
        """攻撃の再現: 攻撃者が自分の認可リクエストの state を、被害者のブラウザに踏ませる。

        攻撃者の認可リクエストに被害者の本人確認が紐づくと、被害者のトークンを攻撃者が
        入手できてしまう。同意画面を開いたブラウザ（Cookie）でなければ、コールバックは拒否する。
        """
        rid = self._pending(http)
        # 攻撃者のブラウザ（http）が、自分の分を許可して state を得る
        state = _github_state(http, rid)
        victim = TestClient(http.app, base_url=ISSUER, follow_redirects=False)  # Cookie なし
        res = _callback(victim, state, login="victim")
        assert res.status_code == 403
        row = db_session.get(OAuthAuthorization, rid)
        # 何も発行されない
        assert row is not None and row.username is None and row.code_hash is None

    def test_callback_clears_the_cookie_on_success(self, http):
        rid = self._pending(http)
        res = _callback(http, _github_state(http, rid))
        assert res.status_code == 302
        assert "mcp_oauth_consent=" in res.headers["set-cookie"].lower()
        assert "max-age=0" in res.headers["set-cookie"].lower()

    def test_same_browser_can_reopen_the_page(self, http):
        rid = self._pending(http)
        _open_consent(http, rid)
        assert _open_consent(http, rid).status_code == 200  # 再読み込みしても見られる

    def test_binding_helpers(self):
        row = OAuthAuthorization(browser_hash=None)
        assert not oauth_flow.is_bound_to(row, "x")
        assert not oauth_flow.is_bound_to(row, None)


class TestAuthorizeValidation:
    def test_unsupported_scope_is_rejected(self, http):
        _, challenge = _pkce()
        res = _authorize(http, _register(http), challenge, scope="admin")
        assert "error=invalid_scope" in res.headers["location"]

    def test_foreign_resource_is_rejected(self, http):
        _, challenge = _pkce()
        res = _authorize(http, _register(http), challenge, resource="https://other.example/mcp")
        assert "error=invalid_request" in res.headers["location"]

    def test_own_resource_is_accepted(self, http):
        _, challenge = _pkce()
        res = _authorize(http, _register(http), challenge, resource=f"{ISSUER}/mcp")
        assert "/oauth/consent" in res.headers["location"]

    def test_unregistered_redirect_uri_is_not_followed(self, http):
        _, challenge = _pkce()
        res = _authorize(http, _register(http), challenge, redirect="http://localhost:1/other")
        # 登録外の redirect_uri へはリダイレクトしない（エラーを直接返す）
        assert res.status_code == 400


class TestCallbackSecurity:
    def test_state_not_signed_by_us_falls_back_to_dashboard_flow(self, http):
        # ダッシュボードのログイン用 state（ランダム値）は Cookie 検証へ進み、Cookie が無ければ 400
        with patch("app.auth.github_router.settings.GITHUB_OAUTH_CLIENT_ID", "gh-client"), \
             patch("app.auth.github_router.settings.GITHUB_OAUTH_CLIENT_SECRET", "gh-secret"):
            res = http.get("/auth/github/callback", params={"code": "c", "state": "random"})
        assert res.status_code == 400

    def test_forged_state_is_rejected(self, http):
        assert oauth_flow.decode_state("garbage") is None
        assert oauth_flow.decode_state(oauth_flow.encode_state("rid") + "x") is None

    def test_state_with_other_audience_is_rejected(self):
        import jwt

        from app.core.config import settings
        forged = jwt.encode(
            {"rid": "r", "exp": datetime.now(UTC) + timedelta(minutes=5)},
            settings.SESSION_SECRET_KEY, algorithm="HS256",
        )
        assert oauth_flow.decode_state(forged) is None

    def test_callback_for_expired_request_is_rejected(self, http, db_session):
        _, challenge = _pkce()
        loc = _authorize(http, _register(http), challenge).headers["location"]
        rid = _request_id(loc)
        state = _github_state(http, rid)
        row = db_session.get(OAuthAuthorization, rid)
        row.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        db_session.commit()
        assert _callback(http, state).status_code == 400

    def test_callback_cannot_be_replayed(self, http):
        _, challenge = _pkce()
        loc = _authorize(http, _register(http), challenge).headers["location"]
        state = _github_state(http, _request_id(loc))
        assert _callback(http, state).status_code == 302
        # 同じ state で2回目: すでに本人が紐づいているため無効
        assert _callback(http, state).status_code == 400

    def test_github_failure_discards_request_and_denies(self, http, db_session):
        import httpx
        _, challenge = _pkce()
        loc = _authorize(http, _register(http), challenge).headers["location"]
        rid = _request_id(loc)
        state = _github_state(http, rid)
        with patch("app.auth.github_router.settings.GITHUB_OAUTH_CLIENT_ID", "gh-client"), \
             patch("app.auth.github_router.settings.GITHUB_OAUTH_CLIENT_SECRET", "gh-secret"), \
             patch(f"{_GH}.settings.GITHUB_OAUTH_CLIENT_ID", "gh-client"), \
             patch(f"{_GH}.exchange_code_for_token", side_effect=httpx.ConnectError("x")):
            res = http.get("/auth/github/callback", params={"code": "c", "state": state})
        assert "error=access_denied" in res.headers["location"]
        assert db_session.get(OAuthAuthorization, rid) is None


class TestTokenExchange:
    def test_code_is_single_use(self, http):
        client_id, code, verifier = _full_flow(http)
        assert _token_request(http, client_id, code, verifier).status_code == 200
        again = _token_request(http, client_id, code, verifier)
        assert again.status_code == 400 and again.json()["error"] == "invalid_grant"

    def test_wrong_pkce_verifier_is_rejected(self, http):
        client_id, code, _ = _full_flow(http)
        res = _token_request(http, client_id, code, secrets.token_urlsafe(48))
        assert res.status_code == 400 and res.json()["error"] == "invalid_grant"

    def test_code_for_another_client_is_rejected(self, http):
        _, code, verifier = _full_flow(http)
        other = _register(http, name="other")
        res = _token_request(http, other, code, verifier)
        assert res.status_code == 400

    def test_expired_code_is_rejected(self, http, db_session):
        client_id, code, verifier = _full_flow(http)
        row = db_session.query(OAuthAuthorization).one()
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db_session.commit()
        assert _token_request(http, client_id, code, verifier).status_code == 400

    def test_unknown_code_is_rejected(self, http):
        client_id = _register(http)
        res = _token_request(http, client_id, "nope", "v" * 50)
        assert res.status_code == 400

    def test_refresh_grant_is_not_supported_yet(self, http):
        client_id = _register(http)
        res = http.post("/token", data={
            "grant_type": "refresh_token", "client_id": client_id, "refresh_token": "x",
        })
        assert res.status_code == 400


class TestLedgerIntegration:
    def test_oauth_tokens_are_hidden_from_manual_list_and_limit(self, http, db_session):
        client_id, code, verifier = _full_flow(http, login="alice")
        assert _token_request(http, client_id, code, verifier).status_code == 200
        db_session.expire_all()
        # 手動発行の一覧・上限には現れない
        assert list_tokens(db_session, "alice") == []
        issue_token(db_session, "alice", 30)
        assert len(list_tokens(db_session, "alice")) == 1

    def test_oauth_tokens_are_excluded_from_expiry_notices(self, http, db_session):
        client_id, code, verifier = _full_flow(http, login="alice")
        _token_request(http, client_id, code, verifier)
        db_session.expire_all()
        # 1時間で切れる OAuth トークンは、期限3日前通知の対象外
        assert find_expiring_tokens(db_session) == {}

    def test_oauth_token_can_be_revoked_individually(self, http, db_session):
        from app.mcp_server.mcp_token_store import revoke_token
        client_id, code, verifier = _full_flow(http, login="alice")
        token = _token_request(http, client_id, code, verifier).json()["access_token"]
        claims = verify_mcp_token(token)
        db_session.expire_all()
        assert revoke_token(db_session, "alice", claims.token_id)
        assert not is_usable(db_session, claims)
        # 他人は失効できない
        assert not revoke_token(db_session, "mallory", claims.token_id)


class TestGrantNotice:
    """接続を許可したら、本人の Slack に事後通知する（登録済みの場合のみ。IPA 6-(ii)）。"""

    _HOOK = "https://hooks.slack.com/services/T000/B000/XXXX"

    def test_notifies_the_user_who_approved(self, http, db_session):
        from app.auth.account_store import set_slack_webhook, upsert_user_token
        from app.auth.models import UserAccount

        upsert_user_token(db_session, "alice", "gho_dummy")
        set_slack_webhook(db_session, "alice", self._HOOK)
        try:
            with patch(f"{_GH}.notify_oauth_connection_granted") as notify:
                _full_flow(http, login="alice", name="Claude Code")
        finally:
            db_session.query(UserAccount).delete()
            db_session.commit()

        notify.assert_called_once_with(self._HOOK, "Claude Code")

    def test_does_not_notify_without_a_registered_webhook(self, http):
        with patch(f"{_GH}.notify_oauth_connection_granted") as notify:
            _full_flow(http, login="alice")

        notify.assert_not_called()

