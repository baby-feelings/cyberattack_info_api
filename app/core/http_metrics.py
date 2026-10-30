"""HTTP リクエストの運用監視メトリクス（Prometheus）。

API が正常に応答しているか（5xx の割合）・遅くなっていないか（応答時間）を、Grafana で見るための
指標。ラベルはステータスの区分（2xx〜5xx）だけにする（パスをラベルにすると、種類が増え続けるため）。
カウンターはプロセスのメモリ上にあり、再起動で 0 に戻るが、Prometheus の `rate()` が吸収する。
"""
import time
from typing import Any

from prometheus_client import Counter, Histogram

# 監視自体のリクエスト（Prometheus のスクレイプ）は、数えない
_EXCLUDED_PATHS = ("/metrics",)

http_requests_total = Counter(
    "http_requests_total", "HTTP リクエストの数（ステータスの区分別）", ["status_class"],
)
http_request_duration_seconds = Histogram(
    "http_request_duration_seconds", "HTTP リクエストの処理時間（秒）",
    buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
)


class HttpMetricsMiddleware:
    """ASGI ミドルウェア。リクエストの数と処理時間を記録する。"""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope["path"] in _EXCLUDED_PATHS:
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        # 応答を返す前に例外で落ちたときは、500 とみなす
        status = 500

        async def send_and_capture(message: dict[str, Any]) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_and_capture)
        finally:
            http_requests_total.labels(status_class=f"{status // 100}xx").inc()
            http_request_duration_seconds.observe(time.perf_counter() - started)
