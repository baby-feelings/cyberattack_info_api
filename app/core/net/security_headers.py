"""全レスポンスにセキュリティ関連の HTTP ヘッダーを付与するミドルウェア。

OWASP ZAP の API Scan で `X-Content-Type-Options Header Missing` が検出されたため追加した。
本 API は JSON を返すのみで、ブラウザに HTML として解釈・埋め込みされる用途は無いため、
次の保守的なヘッダーを一律で付ける。

- X-Content-Type-Options: nosniff        … Content-Type の MIME スニッフィングを禁止する
- X-Frame-Options: DENY                  … iframe への埋め込み（クリックジャッキング）を禁止する
- Referrer-Policy: no-referrer           … 遷移先へ URL（クエリ含む）を漏らさない
- Content-Security-Policy                … JSON だけを返す API なので、何も読み込ませない
  （`API_CSP`）。開発環境の `/docs`・`/redoc`（Swagger UI・ReDoc。本番では無効）だけは、
  CDN のスクリプトを読むため専用（`DOCS_CSP`）。同意画面（`/oauth/consent`）のように、
  ハンドラ側で CSP を決めているレスポンスは上書きしない。
"""
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

# JSON だけを返す API 用。スクリプト・画像・通信などを一切許可せず、埋め込みも禁止する
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

# 開発環境の Swagger UI・ReDoc 用（jsDelivr の CDN とインラインの初期化スクリプト・スタイルを許可）
DOCS_CSP = (
    "default-src 'none'; "
    "script-src 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
    "font-src https://fonts.gstatic.com; "
    "img-src 'self' data: https://fastapi.tiangolo.com https://cdn.jsdelivr.net; "
    "connect-src 'self'; worker-src blob:; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)
_DOCS_PATHS = frozenset({"/docs", "/redoc"})

SECURITY_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """レスポンスに SECURITY_HEADERS を付与する（既にハンドラ側で設定済みの値は上書きしない）。"""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        csp = DOCS_CSP if request.url.path in _DOCS_PATHS else API_CSP
        response.headers.setdefault("Content-Security-Policy", csp)
        return response
