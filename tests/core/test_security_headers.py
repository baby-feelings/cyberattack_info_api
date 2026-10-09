"""app.core.security_headers（セキュリティヘッダー付与ミドルウェア）のテスト。"""
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core.security_headers import SECURITY_HEADERS, SecurityHeadersMiddleware  # noqa: E402


def _client() -> TestClient:
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/ok")
    def ok() -> dict:
        return {"ok": True}

    @app.get("/custom")
    def custom():
        from fastapi.responses import JSONResponse
        return JSONResponse({"ok": True}, headers={"X-Frame-Options": "SAMEORIGIN"})

    return TestClient(app)


def test_adds_security_headers_to_success_response():
    resp = _client().get("/ok")
    for name, value in SECURITY_HEADERS.items():
        assert resp.headers[name] == value


def test_adds_security_headers_to_error_response():
    # 404 などのエラー応答にも付与される（ZAP は 4xx/5xx も検査するため）
    resp = _client().get("/not-found")
    assert resp.status_code == 404
    assert resp.headers["X-Content-Type-Options"] == "nosniff"


def test_does_not_overwrite_header_set_by_handler():
    resp = _client().get("/custom")
    assert resp.headers["X-Frame-Options"] == "SAMEORIGIN"
