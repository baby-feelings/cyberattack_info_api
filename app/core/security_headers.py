"""全レスポンスにセキュリティ関連の HTTP ヘッダーを付与するミドルウェア。

OWASP ZAP の API Scan で `X-Content-Type-Options Header Missing` が検出されたため追加した。
本 API は JSON を返すのみで、ブラウザに HTML として解釈・埋め込みされる用途は無いため、
次の保守的なヘッダーを一律で付ける。

- X-Content-Type-Options: nosniff        … Content-Type の MIME スニッフィングを禁止する
- X-Frame-Options: DENY                  … iframe への埋め込み（クリックジャッキング）を禁止する
- Referrer-Policy: no-referrer           … 遷移先へ URL（クエリ含む）を漏らさない
"""
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

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
        return response
