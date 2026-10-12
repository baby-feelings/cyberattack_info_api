"""ZAP の診断対象に、FastAPI の OpenAPI に載らないエンドポイントを足す（Issue #303）。

`/mcp` と OAuth 2.1 のエンドポイント（`/register`・`/authorize`・`/token`・`/revoke`・
`/oauth/consent`・`/.well-known/*`）は、MCP SDK・Starlette のルートで、FastAPI の
`/openapi.json` に出てこない。ZAP API Scan は OpenAPI の定義から対象を網羅するため、
ZAP 専用の起動ファイル（`deploy/zap/zap_app.py`）が、この定義を `/openapi.json` に追加する。

**本番の API には使わない**（本番の `/openapi.json` は変えない）。定義は ZAP が妥当なリクエストを
組み立てるための例（example）で、実在のクライアントや認可リクエストは指さない。
"""
from typing import Any

from fastapi import FastAPI

_JSON = "application/json"
_FORM = "application/x-www-form-urlencoded"

# MCP の Streamable HTTP は、Accept に JSON と SSE の両方を要求する
_MCP_ACCEPT = "application/json, text/event-stream"


def _query(name: str, example: str) -> dict[str, Any]:
    return {"name": name, "in": "query", "required": True, "schema": {"type": "string"},
            "example": example}


def _form(properties: dict[str, str]) -> dict[str, Any]:
    """urlencoded のリクエスト本文（プロパティ名 → 例）。"""
    return {"required": True, "content": {_FORM: {"schema": {
        "type": "object",
        "properties": {k: {"type": "string", "example": v} for k, v in properties.items()},
    }}}}


_OK = {"200": {"description": "OK"}}
# 同意画面は HTML を返す（ZAP が「想定外の Content-Type」と誤検知しないよう定義で示す）
_HTML_OK = {"200": {"description": "OK", "content": {"text/html": {"schema": {"type": "string"}}}}}

# ZAP の例の値。実在しない ID・コードで、エラー応答の挙動（情報漏えい・入力検証）を診断する
_EXAMPLE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

EXTRA_PATHS: dict[str, dict[str, Any]] = {
    "/mcp": {"post": {
        "summary": "MCP サーバー（JSON-RPC）",
        "parameters": [{"name": "Accept", "in": "header", "required": True,
                        "schema": {"type": "string"}, "example": _MCP_ACCEPT}],
        "requestBody": {"required": True, "content": {_JSON: {"schema": {
            "type": "object", "example": {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        }}}},
        "responses": _OK,
    }},
    "/register": {"post": {
        "summary": "OAuth 動的クライアント登録（RFC 7591）",
        "requestBody": {"required": True, "content": {_JSON: {"schema": {
            "type": "object",
            "example": {
                "redirect_uris": ["http://localhost:33418/callback"],
                "client_name": "zap-scan-client",
                "token_endpoint_auth_method": "none",
            },
        }}}},
        "responses": _OK,
    }},
    "/authorize": {"get": {
        "summary": "OAuth 認可エンドポイント（同意画面へ）",
        "parameters": [
            _query("client_id", "00000000-0000-0000-0000-000000000000"),
            _query("response_type", "code"),
            _query("redirect_uri", "http://localhost:33418/callback"),
            _query("code_challenge", _EXAMPLE_CHALLENGE),
            _query("code_challenge_method", "S256"),
            _query("state", "zap-state"),
        ],
        "responses": _OK,
    }},
    "/token": {"post": {
        "summary": "OAuth トークンエンドポイント",
        "requestBody": _form({
            "grant_type": "authorization_code",
            "client_id": "00000000-0000-0000-0000-000000000000",
            "code": "zap-invalid-code",
            "code_verifier": "zap-invalid-verifier-zap-invalid-verifier-zap-invalid",
            "redirect_uri": "http://localhost:33418/callback",
        }),
        "responses": _OK,
    }},
    "/revoke": {"post": {
        "summary": "OAuth トークンの失効（RFC 7009）",
        "requestBody": _form({
            "token": "zap-invalid-token",
            "client_id": "00000000-0000-0000-0000-000000000000",
        }),
        "responses": _OK,
    }},
    "/oauth/consent": {
        "get": {
            "summary": "OAuth 同意画面",
            "parameters": [_query("request_id", "zap-invalid-request-id")],
            "responses": _HTML_OK,
        },
        "post": {
            "summary": "OAuth 同意画面の許可・拒否",
            "requestBody": _form({"request_id": "zap-invalid-request-id", "action": "approve"}),
            "responses": _HTML_OK,
        },
    },
    "/.well-known/oauth-authorization-server": {"get": {
        "summary": "OAuth 認可サーバーのメタデータ", "responses": _OK,
    }},
    "/.well-known/oauth-protected-resource/mcp": {"get": {
        "summary": "OAuth 保護リソース（MCP）のメタデータ", "responses": _OK,
    }},
}


def extend_openapi(app: FastAPI) -> None:
    """`app.openapi()` が返す定義に EXTRA_PATHS を足す（初回に生成してキャッシュする）。

    すでに FastAPI が定義しているパス・メソッドは上書きしない。
    """
    original = app.openapi

    def _openapi() -> dict[str, Any]:
        if app.openapi_schema is not None:
            return app.openapi_schema
        schema = original()
        paths = schema.setdefault("paths", {})
        for path, methods in EXTRA_PATHS.items():
            target = paths.setdefault(path, {})
            for method, definition in methods.items():
                target.setdefault(method, definition)
        app.openapi_schema = schema
        return schema

    app.openapi = _openapi  # type: ignore[method-assign]
