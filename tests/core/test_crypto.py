"""app.core.crypto（GitHubアクセストークンの暗号化ヘルパー）のテスト。"""
from app.core.crypto import decrypt_token, encrypt_token


def test_encrypt_and_decrypt_round_trip():
    plaintext = "gho_dummyAccessTokenValue"
    ciphertext = encrypt_token(plaintext)
    assert ciphertext != plaintext
    assert decrypt_token(ciphertext) == plaintext


def test_encrypt_raises_when_key_not_configured(monkeypatch):
    monkeypatch.setattr("app.core.crypto.settings.TOKEN_ENCRYPTION_KEY", "")
    try:
        encrypt_token("secret")
        raise AssertionError("expected RuntimeError")
    except RuntimeError:
        pass


def test_decrypt_returns_none_when_key_not_configured(monkeypatch):
    monkeypatch.setattr("app.core.crypto.settings.TOKEN_ENCRYPTION_KEY", "")
    assert decrypt_token("anything") is None


def test_decrypt_returns_none_for_invalid_ciphertext():
    assert decrypt_token("not-a-valid-fernet-token") is None


def test_decrypt_returns_none_when_encrypted_with_different_key(monkeypatch):
    ciphertext = encrypt_token("secret")
    monkeypatch.setattr(
        "app.core.crypto.settings.TOKEN_ENCRYPTION_KEY",
        "wF3q9m5QwQKJf8p2bT6yV1lC0dX7nR4sZ9aH2eU6jKo=",
    )
    assert decrypt_token(ciphertext) is None
