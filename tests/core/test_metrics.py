"""運用監視メトリクスのエンドポイント（app.core.metrics）のテスト。

GET /metrics の認証と、公開される指標を検証する。クローラーの実行結果など DB から求める指標は
`tests/jobs/test_domain_metrics.py` で検証する。
"""
from unittest.mock import patch


class TestMetricsEndpoint:
    def test_returns_503_when_not_configured(self, client):
        with patch("app.core.metrics.settings.METRICS_API_KEY", ""):
            res = client.get("/metrics")
        assert res.status_code == 503

    def test_returns_401_without_credentials(self, client):
        with patch("app.core.metrics.settings.METRICS_API_KEY", "secret-metrics-key"):
            res = client.get("/metrics")
        assert res.status_code == 401

    def test_returns_401_with_wrong_credentials(self, client):
        with patch("app.core.metrics.settings.METRICS_API_KEY", "secret-metrics-key"):
            res = client.get("/metrics", headers={"Authorization": "Bearer wrong-key"})
        assert res.status_code == 401

    def test_returns_200_with_valid_bearer_token(self, client):
        with patch("app.core.metrics.settings.METRICS_API_KEY", "secret-metrics-key"):
            res = client.get(
                "/metrics", headers={"Authorization": "Bearer secret-metrics-key"},
            )
        assert res.status_code == 200
        assert res.headers["content-type"].startswith("text/plain")

    def test_exposes_external_api_retry_metric(self, client):
        """app.core.retryが定義するCounterも、明示的な結線なしに自動的に
        /metricsへ公開されること（prometheus_clientのグローバルレジストリ経由、
        Issue #130）。"""
        with patch("app.core.metrics.settings.METRICS_API_KEY", "secret-metrics-key"):
            res = client.get(
                "/metrics", headers={"Authorization": "Bearer secret-metrics-key"},
            )
        assert res.status_code == 200
        assert "external_api_retry_total" in res.text
