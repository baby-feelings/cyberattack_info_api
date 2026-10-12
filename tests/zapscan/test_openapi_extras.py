"""app.zapscan.openapi_extras（ZAP 用に OpenAPI へ足す /mcp・OAuth の定義）のテスト。"""
import os
from typing import Any
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")
os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret-key-for-pytest")

from fastapi import FastAPI  # noqa: E402

from app.mcp_server import oauth_routes  # noqa: E402
from app.zapscan.openapi_extras import EXTRA_PATHS, extend_openapi  # noqa: E402

_ISSUER = "https://api.example.test"


def _routes(router: Any) -> set[tuple[str, str]]:
    """ルーターに実在するルートの (パス, メソッド) の集合。

    FastAPI は `include_router` したルートを `_IncludedRouter`（`original_router` を持つ入れ物）で
    保持するため、その中も辿る。
    """
    found: set[tuple[str, str]] = set()
    for route in router.routes:
        inner = getattr(route, "original_router", None)
        if inner is not None:
            found |= _routes(inner)
            continue
        for method in getattr(route, "methods", None) or ():
            found.add((getattr(route, "path", ""), method.lower()))
    return found


class TestExtendOpenapi:
    def test_adds_all_extra_paths(self):
        app = FastAPI()
        extend_openapi(app)
        paths = app.openapi()["paths"]
        for path, methods in EXTRA_PATHS.items():
            for method in methods:
                assert method in paths[path], (path, method)

    def test_does_not_override_existing_definitions(self):
        app = FastAPI()

        @app.post("/register")
        def register() -> dict[str, str]:  # FastAPI 自身が定義しているパスは上書きしない
            return {}

        extend_openapi(app)
        assert app.openapi()["paths"]["/register"]["post"]["operationId"].startswith("register")

    def test_schema_is_cached_and_idempotent(self):
        app = FastAPI()
        extend_openapi(app)
        first = app.openapi()
        assert app.openapi() is first

    def test_mcp_example_sends_required_accept_header(self):
        header = EXTRA_PATHS["/mcp"]["post"]["parameters"][0]
        assert header["name"] == "Accept" and "text/event-stream" in header["example"]


class TestNoDriftFromRealRoutes:
    """定義したパス・メソッドが、実際のルートと一致している（ルート名の変更に気づく）。"""

    def test_every_extra_path_exists_in_the_app(self):
        from app.main import app as main_app

        oauth_app = FastAPI()
        with patch.object(oauth_routes.settings, "API_BASE_URL_FOR_OAUTH", _ISSUER):
            assert oauth_routes.mount_oauth_routes(oauth_app, issuer=_ISSUER)
        real = _routes(oauth_app.router) | _routes(main_app.router)

        for path, methods in EXTRA_PATHS.items():
            for method in methods:
                assert (path, method) in real, f"{method.upper()} {path} が実在しない"
