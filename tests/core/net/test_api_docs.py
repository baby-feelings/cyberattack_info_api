"""app.core.net.api_docs（API 仕様の公開方針）のテスト。

本番では、Swagger UI（/docs）・ReDoc（/redoc）だけでなく、
OpenAPI 仕様（/openapi.json）も公開しない。仕様には /admin/* や /auth/* のパスが
全て載り、認証なしで読めると偵察に使われるため。
"""
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core.net.api_docs import docs_urls, root_info  # noqa: E402


def _client(environment: str) -> TestClient:
    """指定した環境の方針で作った、最小の FastAPI アプリのクライアント。"""
    app = FastAPI(**docs_urls(environment))

    @app.get("/ping")
    def ping() -> dict[str, str]:
        return {"ok": "yes"}

    return TestClient(app)


def test_本番は_docs_redoc_openapi_を全て無効にする():
    assert docs_urls("production") == {"docs_url": None, "redoc_url": None, "openapi_url": None}


def test_本番のアプリは_API仕様を公開しない():
    client = _client("production")
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/ping").status_code == 200  # 通常のルートは動く


def test_開発のアプリは_API仕様を公開する():
    client = _client("development")
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200
    assert client.get("/redoc").status_code == 200


def test_ルートの案内は_本番では存在しないリンクを返さない():
    prod = root_info("production")
    assert "docs" not in prod and "redoc" not in prod
    assert prod["health"] == "/health"
    assert prod["name"] == "Cyberattack Info API"


def test_ルートの案内は_開発では_docs_redoc_へのリンクを返す():
    dev = root_info("development")
    assert dev["docs"] == "/docs"
    assert dev["redoc"] == "/redoc"
    assert dev["health"] == "/health"
