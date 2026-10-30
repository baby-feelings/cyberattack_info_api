"""運用監視のメトリクス（Prometheus）のうち、DB の内容から求めるもの。

`GET /metrics`（`app.core.metrics`）が返す指標のうち、各ドメインの状態を表すものを、DB から求める。
core は個別のドメインを知らない方針のため、ドメインを束ねるこの `jobs` に置く。

- **クローラーの直近の実行結果**（`crawler_last_run_*`）: `crawler_logs` の、種別ごとの最新の1行。
  以前はクロール完了時にメモリ上の Gauge を更新していたため、API の再起動（デプロイ）のたびに
  消え、次の実行まで Grafana のパネルが空になっていた。DB から求めるので、再起動で消えない
- **鍵の更新期限までの日数**（`secret_expires_in_days`。設定から求める。DB は使わない）

Grafana は「本アプリが正常に動いているか」の把握に絞る。脆弱性・依存パッケージ・言語の件数は、
Web ダッシュボード（と API）が担うため、ここでは扱わない（重複させない）。

本番 DB（Neon）はアクセスが無いと休止するため、30秒ごとのスクレイプのたびに問い合わせると
常時起動になってしまう。更新は1日1回程度のため、結果は `CACHE_TTL_SECONDS` の間キャッシュする。
"""
import logging
import threading
import time
from collections.abc import Iterable
from datetime import UTC, date, datetime
from typing import Any

from prometheus_client.core import REGISTRY, GaugeMetricFamily
from prometheus_client.registry import Collector
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.crawler_logs.models import CrawlerLog
from app.jobs.secret_expiry import secret_days_left

logger = logging.getLogger(__name__)

# 集計結果をキャッシュする秒数（Neon を常時起動にしないため）
CACHE_TTL_SECONDS = 3600
# 集計に失敗したとき、再び試すまでの秒数（失敗が続いても DB を叩き続けないため）
RETRY_AFTER_FAILURE_SECONDS = 300


def _epoch(moment: datetime) -> float:
    """日時を UNIX 時間にする。タイムゾーンが無い日時（SQLite）は UTC として扱う。"""
    return (moment if moment.tzinfo else moment.replace(tzinfo=UTC)).timestamp()


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


def _secret_expiry_family(today: date | None = None) -> GaugeMetricFamily:
    """鍵（API_KEY・GITHUB_TOKEN）の更新期限までの日数（過ぎていれば負）。期限を決めていない鍵は出さない。"""
    gauge = GaugeMetricFamily(
        "secret_expires_in_days", "鍵の更新期限までの日数（過ぎていれば負の値）", labels=["secret"],
    )
    for name, days_left in secret_days_left(today).items():
        gauge.add_metric([name], days_left)
    return gauge


def build_metric_families() -> list[GaugeMetricFamily]:
    """DB から、全ての指標を求める。"""
    with SessionLocal() as db:
        return [
            *_crawler_families(db),
            _secret_expiry_family(),
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
