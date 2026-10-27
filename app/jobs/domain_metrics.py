"""運用監視のメトリクス（Prometheus）のうち、DB の内容から求めるもの。

`GET /metrics`（`app.core.metrics`）が返す指標のうち、各ドメインの状態を表すものを、DB から求める。
core は個別のドメインを知らない方針のため、ドメインを束ねるこの `jobs` に置く。

- **クローラーの直近の実行結果**（`crawler_last_run_*`）: `crawler_logs` の、種別ごとの最新の1行。
  以前はクロール完了時にメモリ上の Gauge を更新していたため、API の再起動（デプロイ）のたびに
  消え、次の実行まで Grafana のパネルが空になっていた。DB から求めるので、再起動で消えない
- **未解決の脆弱性の件数**（`depscan_open_findings`・`codescan_open_findings`）
- **使っている依存パッケージの数**（`repo_dependencies_total`。SBOM の全量）
- **使っている言語・実行環境の状態別の数**（`runtime_usage`）

`operating` ラベル（active=運用中 / inactive=運用停止中）は、`INACTIVE_REPOS` と照合して付ける。

本番 DB（Neon）はアクセスが無いと休止するため、30秒ごとのスクレイプのたびに問い合わせると
常時起動になってしまう。更新は1日1回程度のため、結果は `CACHE_TTL_SECONDS` の間キャッシュする。
"""
import logging
import threading
import time
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from prometheus_client.core import REGISTRY, GaugeMetricFamily
from prometheus_client.registry import Collector
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.codescan.models import CodeFinding
from app.core.database import SessionLocal
from app.core.operating_status import is_inactive_repo
from app.crawler_logs.models import CrawlerLog
from app.depscan.models import DependencyFinding, RepoDependency
from app.runtimes.browse import list_runtimes

logger = logging.getLogger(__name__)

# 集計結果をキャッシュする秒数（Neon を常時起動にしないため）
CACHE_TTL_SECONDS = 3600
# 集計に失敗したとき、再び試すまでの秒数（失敗が続いても DB を叩き続けないため）
RETRY_AFTER_FAILURE_SECONDS = 300


def _epoch(moment: datetime) -> float:
    """日時を UNIX 時間にする。タイムゾーンが無い日時（SQLite）は UTC として扱う。"""
    return (moment if moment.tzinfo else moment.replace(tzinfo=UTC)).timestamp()


def _operating(repo_full_name: str) -> str:
    """運用状態のラベル値。"""
    return "inactive" if is_inactive_repo(repo_full_name) else "active"


def _crawler_families(db: Session) -> list[GaugeMetricFamily]:
    """クローラー種別ごとの、直近の実行結果。"""
    latest_ids = select(func.max(CrawlerLog.id)).group_by(CrawlerLog.crawler_type)
    rows = db.query(CrawlerLog).filter(CrawlerLog.id.in_(latest_ids)).all()

    def family(name: str, doc: str, value: Any) -> GaugeMetricFamily:
        gauge = GaugeMetricFamily(name, doc, labels=["crawler_type"])
        for row in rows:
            gauge.add_metric([row.crawler_type], value(row))
        return gauge

    return [
        family(
            "crawler_last_run_success",
            "直近のクローラー実行が成功したか（1=success, 0=error）",
            lambda r: 1 if r.status == "success" else 0,
        ),
        family(
            "crawler_last_run_timestamp_seconds",
            "直近のクローラー実行が完了した時刻（UNIX時間）。値の陳腐化検知に使う",
            lambda r: _epoch(r.finished_at),
        ),
        family(
            "crawler_last_run_duration_seconds",
            "直近のクローラー実行にかかった時間（秒）",
            lambda r: r.duration_seconds,
        ),
        family(
            "crawler_last_run_inserted",
            "直近のクローラー実行での新規挿入件数",
            lambda r: r.inserted,
        ),
        family(
            "crawler_last_run_updated",
            "直近のクローラー実行での更新件数",
            lambda r: r.updated,
        ),
        family(
            "crawler_last_run_deleted",
            "直近のクローラー実行での削除件数",
            lambda r: r.deleted,
        ),
    ]


def _open_findings_family(
    db: Session, name: str, doc: str, model: type[DependencyFinding] | type[CodeFinding],
) -> GaugeMetricFamily:
    """未解決の検知の件数（重要度・運用状態別）。"""
    rows = (
        db.query(model.repo_full_name, model.severity, func.count(model.id))
        .filter(model.resolved_at.is_(None))
        .group_by(model.repo_full_name, model.severity)
        .all()
    )
    counts: dict[tuple[str, str], int] = {}
    for repo, severity, count in rows:
        key = (_operating(repo), severity or "N/A")
        counts[key] = counts.get(key, 0) + count
    gauge = GaugeMetricFamily(name, doc, labels=["operating", "severity"])
    for (operating, severity), count in sorted(counts.items()):
        gauge.add_metric([operating, severity], count)
    return gauge


def _dependency_family(db: Session) -> GaugeMetricFamily:
    """使っている依存パッケージの数（運用状態別）。"""
    rows = db.query(RepoDependency.repo_full_name, func.count(RepoDependency.id)).group_by(
        RepoDependency.repo_full_name,
    ).all()
    counts: dict[str, int] = {}
    for repo, count in rows:
        counts[_operating(repo)] = counts.get(_operating(repo), 0) + count
    gauge = GaugeMetricFamily(
        "repo_dependencies_total", "使っている依存パッケージの数（SBOM の全量）",
        labels=["operating"],
    )
    for operating, count in sorted(counts.items()):
        gauge.add_metric([operating], count)
    return gauge


def _runtime_family(db: Session) -> GaugeMetricFamily:
    """使っている言語・実行環境の数（言語・状態・運用状態別）。"""
    today = datetime.now(UTC).date()
    counts: dict[tuple[str, str, str], int] = {}
    for row, status in list_runtimes(db, today=today):
        key = (row.runtime, status.state, _operating(row.repo_full_name))
        counts[key] = counts.get(key, 0) + 1
    gauge = GaugeMetricFamily(
        "runtime_usage",
        "使っている言語・実行環境の数（state: eol / eol_soon / update_available / latest / "
        "reference / unknown）",
        labels=["runtime", "state", "operating"],
    )
    for (runtime, state, operating), count in sorted(counts.items()):
        gauge.add_metric([runtime, state, operating], count)
    return gauge


def build_metric_families() -> list[GaugeMetricFamily]:
    """DB から、全ての指標を求める。"""
    with SessionLocal() as db:
        return [
            *_crawler_families(db),
            _open_findings_family(
                db, "depscan_open_findings", "DEPSCAN の未解決の脆弱性の数", DependencyFinding,
            ),
            _open_findings_family(
                db, "codescan_open_findings", "CODESCAN の未解決の脆弱性の数", CodeFinding,
            ),
            _dependency_family(db),
            _runtime_family(db),
        ]


class DomainMetricsCollector(Collector):
    """DB から求めた指標を、キャッシュ付きで返す Prometheus のコレクタ。"""

    def __init__(self, ttl_seconds: float = CACHE_TTL_SECONDS) -> None:
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._families: list[GaugeMetricFamily] = []
        self._next_refresh = 0.0

    def describe(self) -> Iterable[GaugeMetricFamily]:
        """何も宣言しない。登録時に `collect()` が呼ばれ、DB の準備前に集計されるのを防ぐ。"""
        return []

    def collect(self) -> Iterable[GaugeMetricFamily]:
        with self._lock:
            now = time.monotonic()
            if now >= self._next_refresh:
                try:
                    self._families = build_metric_families()
                    self._next_refresh = now + self._ttl
                except Exception as exc:
                    # 集計の失敗で、/metrics 全体（プロセスの CPU・メモリ等）を止めない。
                    # 直前の結果を返し続け、しばらく後に再び試す
                    logger.error("Failed to build domain metrics: %s", exc, exc_info=True)
                    self._next_refresh = now + RETRY_AFTER_FAILURE_SECONDS
            return list(self._families)


_collector: DomainMetricsCollector | None = None


def register_domain_metrics() -> DomainMetricsCollector:
    """コレクタを Prometheus の既定のレジストリへ登録する（何度呼んでも、1回だけ登録する）。"""
    global _collector
    if _collector is None:
        _collector = DomainMetricsCollector()
        REGISTRY.register(_collector)
    return _collector
