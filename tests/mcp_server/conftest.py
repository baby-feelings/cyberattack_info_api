"""tests/mcp_server 共通のフィクスチャ。

`http`: OAuth 2.1 を有効にし、既存の /auth ルーター（GitHub コールバック）も載せたアプリの
クライアント。認可フロー（test_oauth_flow）・リフレッシュと失効（test_oauth_refresh）が共用する。
"""
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.auth.router import router as auth_router
from app.core.database import get_db
from app.mcp_server import oauth_routes
from tests.conftest import TestSessionLocal

ISSUER = "https://api.example.test"


@pytest.fixture
def http(db_session):
    app = FastAPI()

    def _override_db():
        db = TestSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = _override_db
    original = oauth_routes.SessionLocal
    oauth_routes.SessionLocal = TestSessionLocal
    try:
        # issuer は GitHub コールバックと同じホストであることが必須（起動時に検証される）
        with patch.object(oauth_routes.settings, "API_BASE_URL_FOR_OAUTH", ISSUER):
            assert oauth_routes.mount_oauth_routes(app, issuer=ISSUER)
        app.include_router(auth_router)
        yield TestClient(app, base_url=ISSUER, follow_redirects=False)
    finally:
        oauth_routes.SessionLocal = original
