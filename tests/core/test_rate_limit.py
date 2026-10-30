"""app.core.rate_limit（レート制限・ロックアウト・クライアントの識別。Issue #406）のテスト。"""
# ruff: noqa: E501 - 試験データの表（1行に1件）を、読みやすい形で並べるため
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from unittest.mock import patch  # noqa: E402

from fastapi import FastAPI, HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core import rate_limit  # noqa: E402
from app.core.rate_limit import RateLimiter, RateLimitMiddleware, client_id, is_limited_path  # noqa: E402


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def _limiter(clock, per_minute=3, failures=3, lockout=900.0):
    return RateLimiter(per_minute, failures, lockout, failure_window_seconds=600.0, clock=clock)


class TestRateLimiter:
    def test_requests_over_the_per_minute_limit_are_refused_until_the_window_passes(self):
        clock = _Clock()
        limiter = _limiter(clock)

        assert [limiter.check("a") for _ in range(3)] == [None, None, None]
        retry = limiter.check("a")
        assert retry is not None and 1 <= retry <= 60

        clock.now += 61
        assert limiter.check("a") is None

    def test_clients_are_limited_independently(self):
        limiter = _limiter(_Clock(), per_minute=1)
        assert limiter.check("a") is None and limiter.check("a") is not None
        assert limiter.check("b") is None

    def test_consecutive_failures_lock_the_client_out_for_a_while(self):
        clock = _Clock()
        limiter = _limiter(clock, per_minute=100)

        assert [limiter.record_failure("a") for _ in range(3)] == [False, False, True]
        # ロック中は、すべて拒否する
        assert limiter.check("a") is not None
        clock.now += 899
        assert limiter.check("a") is not None
        clock.now += 2
        assert limiter.check("a") is None
        # ロックが明けたら、失敗の数は、数え直し
        assert limiter.record_failure("a") is False

    def test_old_failures_expire(self):
        clock = _Clock()
        limiter = _limiter(clock)
        limiter.record_failure("a")
        limiter.record_failure("a")
        clock.now += 601                       # 失敗の集計期間（10分）を過ぎる
        assert limiter.record_failure("a") is False

    def test_memory_is_bounded(self):
        limiter = _limiter(_Clock())
        with patch.object(rate_limit, "_MAX_TRACKED_CLIENTS", 5):
            for i in range(20):
                limiter.check(f"c{i}")
                limiter.record_failure(f"c{i}")
        assert len(limiter._requests) <= 5 and len(limiter._failures) <= 5


class TestClientId:
    def test_uses_the_last_forwarded_value_not_the_spoofable_first(self):
        scope = {"headers": [(b"x-forwarded-for", b"6.6.6.6, 1.2.3.4")], "client": ("10.0.0.1", 1)}
        assert client_id(scope) == "1.2.3.4"

    def test_falls_back_to_the_direct_peer_then_unknown(self):
        assert client_id({"headers": [], "client": ("10.0.0.1", 1)}) == "10.0.0.1"
        assert client_id({"headers": [(b"x-forwarded-for", b" , ")], "client": ("10.0.0.2", 1)}) == "10.0.0.2"
        assert client_id({"headers": []}) == "unknown"

    def test_limited_paths(self):
        for path in ("/admin/depscan-crawl", "/auth/mcp-token", "/oauth/consent", "/token", "/register", "/authorize"):
            assert is_limited_path(path) is True, path
        for path in ("/api/kev", "/mcp", "/health", "/metrics", "/administrator"):
            assert is_limited_path(path) is False, path


def _app(limiter):
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, limiter=limiter)

    @app.get("/admin/ping")
    def ping():
        return {"ok": True}

    @app.get("/admin/secret")
    def secret():
        raise HTTPException(status_code=403, detail="no")

    @app.get("/api/open")
    def open_():
        return {"ok": True}

    return TestClient(app)


class TestMiddleware:
    def _enabled(self):
        return patch.object(rate_limit.settings, "RATE_LIMIT_ENABLED", True)

    def test_excess_requests_get_429_with_retry_after_and_other_paths_are_untouched(self):
        client = _app(_limiter(_Clock(), per_minute=2))
        with self._enabled():
            codes = [client.get("/admin/ping").status_code for _ in range(4)]
            blocked = client.get("/admin/ping")
            open_codes = {client.get("/api/open").status_code for _ in range(10)}

        assert codes == [200, 200, 429, 429]
        assert blocked.json()["detail"].startswith("Too many requests") and int(blocked.headers["retry-after"]) >= 1
        assert open_codes == {200}

    def test_repeated_authentication_failures_lock_the_client_out(self):
        client = _app(_limiter(_Clock(), per_minute=100, failures=3))
        with self._enabled():
            failed = [client.get("/admin/secret").status_code for _ in range(3)]
            # 正しい要求も、ロック中は、拒否する
            locked = client.get("/admin/ping").status_code

        assert failed == [403, 403, 403] and locked == 429

    def test_a_spoofed_first_forwarded_value_does_not_bypass_the_limit(self):
        client = _app(_limiter(_Clock(), per_minute=1))
        with self._enabled():
            first = client.get("/admin/ping", headers={"X-Forwarded-For": "1.1.1.1, 9.9.9.9"})
            # 先頭の値を変えても、プロキシが付けた最後の値は同じ → 同じクライアント
            second = client.get("/admin/ping", headers={"X-Forwarded-For": "2.2.2.2, 9.9.9.9"})

        assert (first.status_code, second.status_code) == (200, 429)

    def test_it_can_be_disabled(self):
        client = _app(_limiter(_Clock(), per_minute=1))
        with patch.object(rate_limit.settings, "RATE_LIMIT_ENABLED", False):
            assert {client.get("/admin/ping").status_code for _ in range(5)} == {200}

    def test_non_http_scopes_pass_through_and_the_default_limiter_uses_settings(self):
        limiter = rate_limit.build_limiter()
        assert limiter._per_minute == rate_limit.settings.RATE_LIMIT_PER_MINUTE
        assert limiter._lockout_failures == rate_limit.settings.RATE_LIMIT_LOCKOUT_FAILURES
        assert isinstance(RateLimitMiddleware(app=None)._limiter, RateLimiter)
