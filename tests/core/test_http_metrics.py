"""app.core.http_metrics（HTTP リクエストの運用監視メトリクス）と、レート制限の指標のテスト。"""
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from unittest.mock import patch  # noqa: E402

from prometheus_client import REGISTRY  # noqa: E402

from app.core.rate_limit import RateLimiter  # noqa: E402


def _value(name: str, labels: dict[str, str] | None = None) -> float:
    return REGISTRY.get_sample_value(name, labels or {}) or 0.0


class TestHttpMetrics:
    def test_counts_requests_by_status_class(self, client):
        before_2xx = _value("http_requests_total", {"status_class": "2xx"})
        before_4xx = _value("http_requests_total", {"status_class": "4xx"})
        client.get("/health")
        client.get("/no-such-path")
        assert _value("http_requests_total", {"status_class": "2xx"}) == before_2xx + 1
        assert _value("http_requests_total", {"status_class": "4xx"}) == before_4xx + 1

    def test_observes_the_duration(self, client):
        before = _value("http_request_duration_seconds_count")
        client.get("/health")
        assert _value("http_request_duration_seconds_count") == before + 1

    def test_does_not_count_the_metrics_scrape_itself(self, client):
        before = _value("http_request_duration_seconds_count")
        with patch("app.core.metrics.settings.METRICS_API_KEY", "k"):
            client.get("/metrics", headers={"Authorization": "Bearer k"})
        assert _value("http_request_duration_seconds_count") == before

    def test_an_unhandled_error_is_counted_as_5xx(self):
        import asyncio

        from app.core.http_metrics import HttpMetricsMiddleware

        async def failing_app(scope, receive, send):
            raise RuntimeError("boom")

        before = _value("http_requests_total", {"status_class": "5xx"})
        middleware = HttpMetricsMiddleware(failing_app)
        try:
            asyncio.run(middleware({"type": "http", "path": "/x"}, None, None))
        except RuntimeError:
            pass
        assert _value("http_requests_total", {"status_class": "5xx"}) == before + 1

    def test_non_http_scopes_pass_through(self):
        import asyncio

        from app.core.http_metrics import HttpMetricsMiddleware

        called = []

        async def app(scope, receive, send):
            called.append(scope["type"])

        asyncio.run(HttpMetricsMiddleware(app)({"type": "lifespan"}, None, None))
        assert called == ["lifespan"]


class TestRateLimitMetrics:
    def test_counts_rejections_and_lockouts(self, client):
        rejected = _value("rate_limit_rejected_total")
        lockouts = _value("auth_lockouts_total")
        limiter = RateLimiter(per_minute=1, lockout_failures=2, lockout_seconds=60.0)
        with patch("app.core.rate_limit.build_limiter", return_value=limiter), \
                patch("app.core.rate_limit.settings.RATE_LIMIT_ENABLED", True):
            from fastapi import FastAPI
            from fastapi.testclient import TestClient

            from app.core.rate_limit import RateLimitMiddleware

            app = FastAPI()
            app.add_middleware(RateLimitMiddleware, limiter=limiter)

            @app.get("/admin/x")
            def x():
                from fastapi import HTTPException
                raise HTTPException(status_code=401)

            test_client = TestClient(app)
            test_client.get("/admin/x")  # 1回目: 通る（401）
            test_client.get("/admin/x")  # 2回目: 1分あたりの上限で拒否（429）
        assert _value("rate_limit_rejected_total") == rejected + 1
        # 認証の失敗の連続によるロックアウトは、失敗2回で発動する
        limiter2 = RateLimiter(per_minute=100, lockout_failures=2, lockout_seconds=60.0)
        with patch("app.core.rate_limit.settings.RATE_LIMIT_ENABLED", True):
            from fastapi import FastAPI, HTTPException
            from fastapi.testclient import TestClient

            from app.core.rate_limit import RateLimitMiddleware

            app2 = FastAPI()
            app2.add_middleware(RateLimitMiddleware, limiter=limiter2)

            @app2.get("/admin/y")
            def y():
                raise HTTPException(status_code=403)

            c2 = TestClient(app2)
            c2.get("/admin/y")
            c2.get("/admin/y")
        assert _value("auth_lockouts_total") == lockouts + 1
