"""app.jobs.domain_metrics（DB から求める運用監視メトリクス）のテスト。"""
import os
from datetime import UTC, date, datetime
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.codescan.models import CodeFinding  # noqa: E402
from app.crawler_logs.models import CrawlerLog  # noqa: E402
from app.depscan.models import RepoDependency  # noqa: E402
from app.jobs import domain_metrics  # noqa: E402
from app.jobs.domain_metrics import DomainMetricsCollector  # noqa: E402
from app.runtimes.models import RepoRuntime, RuntimeRelease  # noqa: E402
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


class TestFindingMetrics:
    def test_counts_only_unresolved_by_operating_and_severity(self, db_session):
        make_finding(db_session, repo_full_name="alice/web", severity="HIGH", osv_id="G-1")
        make_finding(db_session, repo_full_name="alice/web", severity="HIGH", osv_id="G-2")
        make_finding(db_session, repo_full_name="alice/old", severity="CRITICAL", osv_id="G-3")
        make_finding(
            db_session, repo_full_name="alice/web", severity="LOW", osv_id="G-4",
            resolved_at=_T1,
        )
        make_finding(db_session, repo_full_name="alice/web", severity=None, osv_id="G-5")

        with patch("app.core.operating_status.settings.INACTIVE_REPOS", "alice/old"):
            samples = _samples(DomainMetricsCollector())

        assert samples["depscan_open_findings"] == {
            ("active", "HIGH"): 2,
            ("active", "N/A"): 1,
            ("inactive", "CRITICAL"): 1,
        }

    def test_codescan_findings(self, db_session):
        db_session.add(CodeFinding(
            repo_full_name="alice/web", file_path="a.py", line_start=1, line_end=1,
            rule_id="r", message="m", severity="ERROR", cwe_ids=[], owasp_categories=[],
            code_snippet="x", cvss_score=None, cvss_vector=None, detected_at=_T0,
        ))
        db_session.commit()

        samples = _samples(DomainMetricsCollector())

        assert samples["codescan_open_findings"] == {("active", "ERROR"): 1}


class TestDependencyAndRuntimeMetrics:
    def test_counts_dependencies_by_operating(self, db_session):
        for repo, name in (("alice/web", "a"), ("alice/web", "b"), ("alice/old", "c")):
            db_session.add(RepoDependency(
                repo_full_name=repo, ecosystem="npm", package_name=name, version="1.0.0",
                manifest_path="package-lock.json",
            ))
        db_session.commit()

        with patch("app.core.operating_status.settings.INACTIVE_REPOS", "alice/old"):
            samples = _samples(DomainMetricsCollector())

        assert samples["repo_dependencies_total"] == {("active",): 2, ("inactive",): 1}

    def test_counts_runtimes_by_state(self, db_session):
        db_session.add_all([
            RuntimeRelease(
                runtime="python", cycle="3.10", latest_version="3.10.20",
                eol_date=date(2026, 10, 1), is_eol=True, is_lts=False,
            ),
            RuntimeRelease(
                runtime="python", cycle="3.13", latest_version="3.13.17",
                eol_date=date(2029, 10, 31), is_eol=False, is_lts=False,
            ),
            RepoRuntime(repo_full_name="alice/web", runtime="python", cycle="3.10",
                        source_path="Dockerfile", pinned=True),
            RepoRuntime(repo_full_name="alice/web", runtime="python", cycle="3.13",
                        source_path="ci.yml", pinned=True),
        ])
        db_session.commit()

        samples = _samples(DomainMetricsCollector())

        assert samples["runtime_usage"] == {
            ("python", "eol", "active"): 1,
            ("python", "latest", "active"): 1,
        }


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
