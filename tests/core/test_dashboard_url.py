"""設定の `DASHBOARD_URL` が、Slack 通知のリンクと CORS に使われることのテスト。"""
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.core.notifications import slack  # noqa: E402


class TestDashboardUrl:
    def test_default_is_the_production_dashboard(self):
        assert slack.DASHBOARD_URL == "https://cyberattackinfoapi.vercel.app/"

    def test_notification_link_always_ends_with_a_slash(self):
        """設定は末尾スラッシュなしで持つ。通知のリンクは、末尾をスラッシュにそろえる。"""
        assert slack.dashboard_link("https://example.test") == "https://example.test/"
        assert slack.dashboard_link("https://example.test/") == "https://example.test/"

    def test_cors_allows_the_configured_dashboard_origin(self, client):
        res = client.options(
            "/health",
            headers={
                "Origin": "https://cyberattackinfoapi.vercel.app",
                "Access-Control-Request-Method": "GET",
            },
        )
        allowed = res.headers.get("access-control-allow-origin")
        assert allowed == "https://cyberattackinfoapi.vercel.app"

    def test_cors_rejects_other_origins(self, client):
        res = client.options(
            "/health",
            headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
        )
        assert res.headers.get("access-control-allow-origin") is None
