"""app.jobs.domain_metrics（DB から求める運用監視メトリクス）のテスト。"""
import os
from datetime import UTC, date, datetime
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.crawler_logs.models import CrawlerLog  # noqa: E402
from app.jobs import domain_metrics  # noqa: E402
from app.jobs.domain_metrics import DomainMetricsCollector  # noqa: E402
from tests.depscan.support import make_finding  # noqa: E402

_T0 = datetime(2026, 6, 15, 19, 0, 0, tzinfo=UTC)
_T1 = datetime(2026, 6, 15, 19, 1, 30, tzinfo=UTC)  # 90 秒後


def _samples(collector: DomainMetricsCollector) -> dict[str, dict[tuple, float]]:
    """{指標名: {ラベル値の組: 値}} にして返す。"""
    result: dict[str, dict[tuple, float]] = {}
    for family in collector.collect():
        for sample in family.samples:
            result.setdefault(sample.name, {})[tuple(sample.labels.values())] = sample.value
    return result


def _all_samples(collector: DomainMetricsCollector):
    return [sample for family in collector.collect() for sample in family.samples]


def _log(db, crawler_type, status="success", *, inserted=0, finished=_T1, duration=90.0):
    db.add(CrawlerLog(
        crawler_type=crawler_type, status=status, started_at=_T0, finished_at=finished,
        duration_seconds=duration, inserted=inserted, updated=0, deleted=0,
    ))
    db.commit()


class TestCrawlerMetrics:
    def test_uses_the_latest_run_per_crawler_type(self, db_session):
        _log(db_session, "KEV", "error", inserted=1)
        _log(db_session, "KEV", "success", inserted=5)
        _log(db_session, "RUNTIME", "error")

        samples = _samples(DomainMetricsCollector())

        assert samples["crawler_last_run_success"] == {("KEV",): 1, ("RUNTIME",): 0}
        assert samples["crawler_last_run_inserted"][("KEV",)] == 5
        assert samples["crawler_last_run_duration_seconds"][("KEV",)] == 90.0
        assert samples["crawler_last_run_timestamp_seconds"][("KEV",)] == _T1.timestamp()

    def test_survives_without_any_run(self, db_session):
        """クローラーの実行記録が無くても、例外にせず、空で返す。"""
        samples = _samples(DomainMetricsCollector())
        assert "crawler_last_run_success" not in samples


class TestSecretExpiryMetrics:
    def test_days_until_each_configured_expiry(self):
        with (
            patch("app.jobs.secret_expiry.settings.API_KEY_EXPIRES_ON", "2026-07-01"),
            patch("app.jobs.secret_expiry.settings.GITHUB_TOKEN_EXPIRES_ON", "2026-06-10"),
        ):
            family = domain_metrics._secret_expiry_family(today=date(2026, 6, 15))
        values = {sample.labels["secret"]: sample.value for sample in family.samples}
        # 過ぎた期限は負の値になる
        assert values == {"API_KEY": 16, "GITHUB_TOKEN": -5}

    def test_secret_without_an_expiry_is_not_exposed(self):
        with (
            patch("app.jobs.secret_expiry.settings.API_KEY_EXPIRES_ON", ""),
            patch("app.jobs.secret_expiry.settings.GITHUB_TOKEN_EXPIRES_ON", ""),
        ):
            family = domain_metrics._secret_expiry_family(today=date(2026, 6, 15))
        assert family.samples == []


class TestRemovedDomainMetrics:
    def test_vulnerability_and_runtime_counts_are_left_to_the_web_dashboard(self, db_session):
        make_finding(db_session)
        names = {sample.name for sample in _all_samples(DomainMetricsCollector())}
        assert not names & {"depscan_open_findings", "codescan_open_findings",
                            "repo_dependencies_total", "runtime_usage"}


class TestCaching:
    def test_does_not_query_again_within_the_ttl(self):
        collector = DomainMetricsCollector(ttl_seconds=3600)
        with patch.object(domain_metrics, "build_metric_families", return_value=[]) as build:
            collector.collect()
            collector.collect()
        assert build.call_count == 1

    def test_refreshes_after_the_ttl(self):
        collector = DomainMetricsCollector(ttl_seconds=0)
        with patch.object(domain_metrics, "build_metric_families", return_value=[]) as build:
            collector.collect()
            collector.collect()
        assert build.call_count == 2

    def test_failure_keeps_previous_result_and_backs_off(self):
        collector = DomainMetricsCollector(ttl_seconds=0)
        with patch.object(domain_metrics, "build_metric_families", return_value=["ok"]):
            assert collector.collect() == ["ok"]
        with patch.object(
            domain_metrics, "build_metric_families", side_effect=RuntimeError("db down"),
        ) as build:
            # 失敗しても、直前の結果を返し、/metrics 全体を止めない
            assert collector.collect() == ["ok"]
            # 失敗の直後は、すぐには再び問い合わせない
            assert collector.collect() == ["ok"]
        assert build.call_count == 1


class TestRegistration:
    def test_registering_does_not_query_the_database(self):
        """Prometheus は登録時に collect() を呼んで指標名を調べる。その時点（起動直後）で集計して
        結果をキャッシュしないよう、describe() は何も集計しない。"""
        collector = DomainMetricsCollector()
        with patch.object(domain_metrics, "build_metric_families") as build:
            assert list(collector.describe()) == []
        build.assert_not_called()

    def test_registration_is_idempotent(self):
        """何度呼んでも、同じ指標名の重複登録（ValueError）にならない。"""
        first = domain_metrics.register_domain_metrics()
        assert domain_metrics.register_domain_metrics() is first


class TestMetricsEndpoint:
    def test_exposes_domain_metrics_through_the_endpoint(self, client, db_session):
        _log(db_session, "KEV", inserted=5)
        # 登録済みのコレクタは結果をキャッシュするため、他のテストで作られた古い結果を捨てる
        domain_metrics.register_domain_metrics()._next_refresh = 0.0
        with patch("app.core.metrics.settings.METRICS_API_KEY", "secret-metrics-key"):
            res = client.get("/metrics", headers={"Authorization": "Bearer secret-metrics-key"})
        assert res.status_code == 200
        # サンプルの無い指標は出力されないため、データがある指標だけを確かめる
        assert 'crawler_last_run_inserted{crawler_type="KEV"} 5.0' in res.text
