"""本番で、公開 URL（DASHBOARD_URL・API_BASE_URL_FOR_OAUTH）が localhost のままの起動を弾くテスト。

設定の既定値は開発用（localhost）。本番の設定漏れで、ログインのリダイレクトや通知のリンクが
開発用の URL を向く不具合を、起動時（Fail Fast）に気づけるようにする。
"""
import os

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from pydantic import ValidationError  # noqa: E402

from app.core.config import Settings  # noqa: E402

_PUBLIC = {
    "DASHBOARD_URL": "https://dashboard.example.test",
    "API_BASE_URL_FOR_OAUTH": "https://api.example.test",
}


@pytest.fixture(autouse=True)
def _no_url_env(monkeypatch):
    """conftest（と実行環境）が設定する環境変数を外し、既定値・明示した値だけで検証する。"""
    monkeypatch.delenv("DASHBOARD_URL", raising=False)
    monkeypatch.delenv("API_BASE_URL_FOR_OAUTH", raising=False)


def _settings(environment: str, **overrides: str) -> Settings:
    """環境変数・.env を読まず、必須項目と指定した値だけで作る。"""
    return Settings(  # type: ignore[call-arg]
        DATABASE_URL="sqlite:///x.db", API_KEY="k", GITHUB_USERNAME="u",
        ENVIRONMENT=environment, _env_file=None, **overrides,
    )


class TestDefaults:
    def test_defaults_point_at_local_development(self):
        s = _settings("development")
        assert s.DASHBOARD_URL == "http://localhost:5173"
        assert s.API_BASE_URL_FOR_OAUTH == "http://localhost:8000"

    def test_development_accepts_localhost(self):
        _settings("development")  # 送出しない


class TestProduction:
    def test_accepts_public_urls(self):
        s = _settings("production", **_PUBLIC)
        assert s.DASHBOARD_URL == "https://dashboard.example.test"

    @pytest.mark.parametrize("missing", ["DASHBOARD_URL", "API_BASE_URL_FOR_OAUTH"])
    def test_rejects_the_default_localhost(self, missing):
        values = {k: v for k, v in _PUBLIC.items() if k != missing}
        with pytest.raises(ValidationError, match=missing):
            _settings("production", **values)

    @pytest.mark.parametrize("url", [
        "http://localhost:5173", "http://127.0.0.1:8000", "http://localhost", "https://[::1]:8000",
    ])
    def test_rejects_any_local_host(self, url):
        with pytest.raises(ValidationError, match="DASHBOARD_URL"):
            _settings("production", **{**_PUBLIC, "DASHBOARD_URL": url})
