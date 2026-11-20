"""API 仕様（Swagger UI・ReDoc・OpenAPI 仕様）の公開方針。

本番では、3 つとも公開しない。Swagger UI（/docs）と ReDoc（/redoc）だけを閉じても、
OpenAPI 仕様（/openapi.json）が見えたままだと、/admin/* や /auth/* を含む全パスが、
認証なしで読めてしまう（偵察の手間を省く情報の露出）。開発環境では、全て公開する。
"""

from typing import TypedDict

PRODUCTION = "production"


class DocsUrls(TypedDict):
    """`FastAPI(...)` の、API 仕様の公開先の引数（None なら公開しない）。"""

    docs_url: str | None
    redoc_url: str | None
    openapi_url: str | None


def docs_urls(environment: str) -> DocsUrls:
    """`FastAPI(**docs_urls(env))` に渡す、仕様の公開先（None なら公開しない）。"""
    if environment == PRODUCTION:
        return {"docs_url": None, "redoc_url": None, "openapi_url": None}
    return {"docs_url": "/docs", "redoc_url": "/redoc", "openapi_url": "/openapi.json"}


def root_info(environment: str) -> dict[str, str]:
    """`GET /` の案内。本番では、存在しない（404 になる）仕様へのリンクを返さない。"""
    info = {"name": "Cyberattack Info API", "version": "1.0.0"}
    if environment != PRODUCTION:
        info["docs"] = "/docs"
        info["redoc"] = "/redoc"
    info["health"] = "/health"
    return info
