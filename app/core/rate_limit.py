"""管理 API・認証系のレート制限と、認証の失敗の連続によるロックアウト（Issue #406）。

`/admin/*` と認証系（`/auth/*`・OAuth）は、総当たり（APIキー・トークンの推測）や、過剰な呼び出しの
標的になる。クライアントごとに、次の2つで制限する。

1. 1分あたりのリクエスト数の上限（超えたら 429）
2. 認証の失敗（401・403）が、一定時間に一定回数を超えたら、一時的にロック
   （429。しばらく、すべて拒否）

状態は、プロセスのメモリに持つ（本アプリは、1つのコンテナで動くため、共有の保存先は要らない。YAGNI）。
再起動で消えるが、攻撃を止める用途には十分。複数のコンテナにするときは、共有の保存先に替える。

クライアントの識別は、リバースプロキシ（Caddy）が付ける `X-Forwarded-For` の **最後の値**
（プロキシが追加した、直前の接続元）を使う。先頭の値は、クライアントが自由に書けるため、使わない（偽ると、制限を
すり抜けられる）。ヘッダーが無ければ、直接の接続元を使う。
"""
import json
import threading
import time
from collections import deque
from collections.abc import Callable, MutableMapping
from typing import Any

from app.core.config import settings

# 制限の対象（これらの前方一致）。公開の読み取り API・MCP（高頻度）・ヘルスチェックは、対象外
RATE_LIMITED_PREFIXES = ("/admin/", "/auth/", "/oauth/", "/token", "/register", "/authorize")
# 認証の失敗とみなす応答
FAILURE_STATUSES = (401, 403)
# 状態を持つクライアントの上限（メモリが、際限なく増えないように）
_MAX_TRACKED_CLIENTS = 10_000
_WINDOW_SECONDS = 60.0


class RateLimiter:
    """クライアントごとの、リクエスト数の上限と、認証失敗のロックアウト。"""

    def __init__(
        self, per_minute: int, lockout_failures: int, lockout_seconds: float,
        failure_window_seconds: float = 600.0, clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._per_minute = per_minute
        self._lockout_failures = lockout_failures
        self._lockout_seconds = lockout_seconds
        self._failure_window = failure_window_seconds
        self._clock = clock
        self._requests: dict[str, deque[float]] = {}
        self._failures: dict[str, deque[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def check(self, client: str) -> int | None:
        """リクエストを数え、拒否すべきなら、再試行までの秒数を返す（許可なら None）。"""
        now = self._clock()
        with self._lock:
            until = self._locked_until.get(client)
            if until is not None:
                if now < until:
                    return max(1, int(until - now))
                del self._locked_until[client]
            window = self._requests.setdefault(client, deque())
            while window and window[0] <= now - _WINDOW_SECONDS:
                window.popleft()
            if len(window) >= self._per_minute:
                return max(1, int(window[0] + _WINDOW_SECONDS - now))
            window.append(now)
            self._bound(self._requests)
            return None

    def record_failure(self, client: str) -> bool:
        """認証の失敗を数える。ロックアウトを始めたら True。"""
        now = self._clock()
        with self._lock:
            failures = self._failures.setdefault(client, deque())
            while failures and failures[0] <= now - self._failure_window:
                failures.popleft()
            failures.append(now)
            self._bound(self._failures)
            if len(failures) >= self._lockout_failures:
                self._locked_until[client] = now + self._lockout_seconds
                failures.clear()
                return True
            return False

    @staticmethod
    def _bound(state: MutableMapping[str, Any]) -> None:
        """追跡するクライアントが多すぎるときは、古いものから捨てる（挿入順）。"""
        while len(state) > _MAX_TRACKED_CLIENTS:
            del state[next(iter(state))]


def client_id(scope: dict[str, Any]) -> str:
    """クライアントの識別子（`X-Forwarded-For` の最後の値、無ければ直接の接続元）。"""
    for name, value in scope.get("headers", []):
        if name == b"x-forwarded-for":
            parts = [p.strip() for p in value.decode("latin-1").split(",") if p.strip()]
            if parts:
                return parts[-1]
    client = scope.get("client")
    return str(client[0]) if client else "unknown"


def is_limited_path(path: str) -> bool:
    return path.startswith(RATE_LIMITED_PREFIXES)


def build_limiter() -> RateLimiter:
    """設定（`RATE_LIMIT_*`）から、制限器を作る。"""
    return RateLimiter(
        per_minute=settings.RATE_LIMIT_PER_MINUTE,
        lockout_failures=settings.RATE_LIMIT_LOCKOUT_FAILURES,
        lockout_seconds=settings.RATE_LIMIT_LOCKOUT_MINUTES * 60.0,
    )


class RateLimitMiddleware:
    """ASGI ミドルウェア。対象のパスだけを制限し、認証の失敗（401・403）を数える。"""

    def __init__(self, app: Any, limiter: RateLimiter | None = None) -> None:
        self.app = app
        self._limiter = limiter or build_limiter()

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if (
            scope["type"] != "http" or not settings.RATE_LIMIT_ENABLED
            or not is_limited_path(scope["path"])
        ):
            await self.app(scope, receive, send)
            return

        client = client_id(scope)
        retry_after = self._limiter.check(client)
        if retry_after is not None:
            body = json.dumps({"detail": "Too many requests. Try again later."}).encode()
            await send({"type": "http.response.start", "status": 429, "headers": [
                (b"content-type", b"application/json"), (b"retry-after", str(retry_after).encode()),
                (b"content-length", str(len(body)).encode()),
            ]})
            await send({"type": "http.response.body", "body": body})
            return

        async def send_and_count(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start" and message["status"] in FAILURE_STATUSES:
                self._limiter.record_failure(client)
            await send(message)

        await self.app(scope, receive, send_and_count)
