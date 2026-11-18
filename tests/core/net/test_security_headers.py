"""app.core.net.security_headers（セキュリティヘッダー付与ミドルウェア）のテスト。"""
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core.net.security_headers import (  # noqa: E402
    API_CSP,
    DOCS_CSP,
    SECURITY_HEADERS,
    SecurityHeadersMiddleware,
)


def _client() -> TestClient:
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/ok")
    def ok() -> dict:
        return {"ok": True}

    @app.get("/docs")
    def docs() -> dict:
        return {"docs": True}

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


def test_json_responses_get_a_strict_csp():
    """JSON だけを返す API には、何も読み込ませない CSP を付ける（外形監視の missing-csp 対応）。"""
    resp = _client().get("/ok")
    assert resp.headers["Content-Security-Policy"] == API_CSP
    assert "default-src 'none'" in API_CSP and "frame-ancestors 'none'" in API_CSP


def test_error_responses_also_get_the_csp():
    assert _client().get("/not-found").headers["Content-Security-Policy"] == API_CSP


def test_swagger_docs_get_their_own_csp_allowing_the_cdn():
    """開発環境の /docs（Swagger UI）は、CDN のスクリプトを読むため、専用の CSP にする。"""
    resp = _client().get("/docs")
    assert resp.headers["Content-Security-Policy"] == DOCS_CSP
    assert "https://cdn.jsdelivr.net" in DOCS_CSP and "frame-ancestors 'none'" in DOCS_CSP
    assert DOCS_CSP != API_CSP
