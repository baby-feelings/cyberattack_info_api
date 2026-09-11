"""運用監視メトリクス（app.core.metrics）のテスト。

GET /metrics の認証・record_crawler_run() によるGauge更新・
write_crawler_log() からの呼び出し連携を検証する。
"""
from datetime import datetime, timezone
from unittest.mock import patch

from app.core.metrics import (
    crawler_last_run_deleted,
    crawler_last_run_duration_seconds,
    crawler_last_run_inserted,
    crawler_last_run_success,
    crawler_last_run_timestamp_seconds,
    crawler_last_run_updated,
    record_crawler_run,
)
from app.crawler_logs.writer import write_crawler_log

_T0 = datetime(2026, 6, 15, 19, 0, 0, tzinfo=timezone.utc)
_T1 = datetime(2026, 6, 15, 19, 1, 30, tzinfo=timezone.utc)  # 90 秒後


class TestRecordCrawlerRun:
    def test_success_run_sets_gauges(self):
        record_crawler_run(
            crawler_type="KEV",
            status="success",
            duration_seconds=90.0,
            inserted=5,
            updated=2,
            deleted=0,
            finished_at_timestamp=_T1.timestamp(),
        )
        assert crawler_last_run_success.labels(crawler_type="KEV")._value.get() == 1
        assert (
            crawler_last_run_duration_seconds.labels(crawler_type="KEV")._value.get() == 90.0
        )
        assert crawler_last_run_inserted.labels(crawler_type="KEV")._value.get() == 5
        assert crawler_last_run_updated.labels(crawler_type="KEV")._value.get() == 2
        assert crawler_last_run_deleted.labels(crawler_type="KEV")._value.get() == 0
        assert (
            crawler_last_run_timestamp_seconds.labels(crawler_type="KEV")._value.get()
            == _T1.timestamp()
        )

    def test_error_run_sets_success_gauge_to_zero(self):
        record_crawler_run(
            crawler_type="OSV",
            status="error",
            duration_seconds=5.0,
            inserted=0,
            updated=0,
            deleted=0,
            finished_at_timestamp=_T1.timestamp(),
        )
        assert crawler_last_run_success.labels(crawler_type="OSV")._value.get() == 0

    def test_different_crawler_types_have_independent_labels(self):
        record_crawler_run(
            crawler_type="JVN", status="success", duration_seconds=1.0,
            inserted=1, updated=0, deleted=0, finished_at_timestamp=_T1.timestamp(),
        )
        record_crawler_run(
            crawler_type="DEPSCAN", status="error", duration_seconds=2.0,
            inserted=0, updated=0, deleted=0, finished_at_timestamp=_T1.timestamp(),
        )
        assert crawler_last_run_success.labels(crawler_type="JVN")._value.get() == 1
        assert crawler_last_run_success.labels(crawler_type="DEPSCAN")._value.get() == 0


class TestWriteCrawlerLogMetricsIntegration:
    def test_write_crawler_log_updates_metrics(self, db_session):
        write_crawler_log(
            crawler_type="DEPSOPS",
            status="success",
            started_at=_T0,
            finished_at=_T1,
            inserted=3,
            updated=1,
            deleted=0,
        )
        assert crawler_last_run_success.labels(crawler_type="DEPSOPS")._value.get() == 1
        assert (
            crawler_last_run_duration_seconds.labels(crawler_type="DEPSOPS")._value.get() == 90.0
        )

    def test_metrics_recording_failure_does_not_break_log_write(self, db_session):
        """メトリクス記録が例外を送出しても、DBへのログ書き込み自体は成功すること。"""
        with patch(
            "app.crawler_logs.writer.record_crawler_run", side_effect=RuntimeError("boom"),
        ):
            # 例外が外に伝播しないことを確認する
            write_crawler_log(
                crawler_type="KEV",
                status="success",
                started_at=_T0,
                finished_at=_T1,
            )


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
        assert "crawler_last_run_success" in res.text

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
