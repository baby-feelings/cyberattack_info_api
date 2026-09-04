"""API キー認証（app.core.auth）のテスト。
require_api_key（管理者用・単一キー）と require_public_api_key
（管理者用キー or 公開ダッシュボード用キーを許可）の挙動を検証する。
"""
import pytest
from fastapi import HTTPException

from app.core.auth import require_api_key, require_public_api_key
from app.core.config import settings

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
