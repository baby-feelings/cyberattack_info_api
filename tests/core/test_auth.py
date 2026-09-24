"""API キー認証（app.core.auth）のテスト。
require_api_key（管理者用・単一キー）、require_public_api_key
（管理者用キー or 公開ダッシュボード用キーを許可）、require_api_key_or_session
（管理者用キー or GitHub ログインセッション JWT を許可。DEPSCAN/CODESCAN 共通）
の挙動を検証する。
"""
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")
os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret-key-for-pytest")

import pytest  # noqa: E402
from fastapi import HTTPException  # noqa: E402

from app.auth.session import create_session_token  # noqa: E402
from app.core.auth import (  # noqa: E402
    require_api_key,
    require_api_key_or_session,
    require_public_api_key,
)
from app.core.config import settings  # noqa: E402

# ── require_api_key（管理者用。settings.API_KEY のみ許可） ─────────

def test_require_api_key_accepts_admin_key():
    assert require_api_key(settings.API_KEY) == settings.API_KEY


def test_require_api_key_rejects_missing_key():
    with pytest.raises(HTTPException) as exc_info:
        require_api_key("")
    assert exc_info.value.status_code == 403


def test_require_api_key_rejects_wrong_key():
    with pytest.raises(HTTPException) as exc_info:
        require_api_key("wrong-key")
    assert exc_info.value.status_code == 403


def test_require_api_key_rejects_public_key_even_when_configured(monkeypatch):
    # /admin/* を保護する require_api_key は、公開ダッシュボード用キーを受け付けない
    # （PUBLIC_API_KEY がブラウザの JS バンドルから漏洩しても管理操作はできないことの担保）
    monkeypatch.setattr(settings, "PUBLIC_API_KEY", "public-key-for-dashboard")
    with pytest.raises(HTTPException) as exc_info:
        require_api_key("public-key-for-dashboard")
    assert exc_info.value.status_code == 403


# ── require_public_api_key（読み取り専用。管理者用キー or 公開キーを許可） ──

def test_require_public_api_key_accepts_admin_key():
    assert require_public_api_key(settings.API_KEY) == settings.API_KEY


def test_require_public_api_key_accepts_public_key_when_configured(monkeypatch):
    monkeypatch.setattr(settings, "PUBLIC_API_KEY", "public-key-for-dashboard")
    assert require_public_api_key("public-key-for-dashboard") == "public-key-for-dashboard"


def test_require_public_api_key_rejects_public_key_when_not_configured(monkeypatch):
    monkeypatch.setattr(settings, "PUBLIC_API_KEY", "")
    with pytest.raises(HTTPException) as exc_info:
        require_public_api_key("some-key-nobody-set")
    assert exc_info.value.status_code == 403


def test_require_public_api_key_rejects_missing_key():
    with pytest.raises(HTTPException) as exc_info:
        require_public_api_key("")
    assert exc_info.value.status_code == 403


def test_require_public_api_key_rejects_wrong_key(monkeypatch):
    monkeypatch.setattr(settings, "PUBLIC_API_KEY", "public-key-for-dashboard")
    with pytest.raises(HTTPException) as exc_info:
        require_public_api_key("totally-wrong-key")
    assert exc_info.value.status_code == 403


# ── require_api_key_or_session（DEPSCAN/CODESCAN 共通。管理者用キー or ────
#    GitHubログインセッションJWT を許可。DEPSCANの旧_resolve_accessと同一ロジック） ──

def test_require_api_key_or_session_accepts_admin_key_and_returns_none():
    # API キー認証時は None を返す（絞り込みなし＝フルアクセスの意）
    assert require_api_key_or_session(api_key=settings.API_KEY, authorization="") is None


def test_require_api_key_or_session_accepts_valid_session_token():
    token = create_session_token("octocat")
    username = require_api_key_or_session(api_key="", authorization=f"Bearer {token}")
    assert username == "octocat"


def test_require_api_key_or_session_accepts_lowercase_bearer_prefix():
    token = create_session_token("octocat")
    username = require_api_key_or_session(api_key="", authorization=f"bearer {token}")
    assert username == "octocat"


def test_require_api_key_or_session_rejects_invalid_session_token():
    with pytest.raises(HTTPException) as exc_info:
        require_api_key_or_session(api_key="", authorization="Bearer not-a-real-token")
    assert exc_info.value.status_code == 403


def test_require_api_key_or_session_rejects_missing_credentials():
    with pytest.raises(HTTPException) as exc_info:
        require_api_key_or_session(api_key="", authorization="")
    assert exc_info.value.status_code == 403


def test_require_api_key_or_session_rejects_wrong_api_key():
    with pytest.raises(HTTPException) as exc_info:
        require_api_key_or_session(api_key="wrong-key", authorization="")
    assert exc_info.value.status_code == 403


def test_require_api_key_or_session_rejects_public_key_even_when_configured(monkeypatch):
    # DEPSCAN/CODESCAN 用の共通認証は PUBLIC_API_KEY を受け付けない（require_api_key
    # と同じ方針。ログイン必須化されたエンドポイントに読み取り専用公開キーは不要）
    monkeypatch.setattr(settings, "PUBLIC_API_KEY", "public-key-for-dashboard")
    with pytest.raises(HTTPException) as exc_info:
        require_api_key_or_session(api_key="public-key-for-dashboard", authorization="")
    assert exc_info.value.status_code == 403
