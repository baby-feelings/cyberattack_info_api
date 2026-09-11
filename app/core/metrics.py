"""運用監視のメトリクスエンドポイント（Prometheus形式）。

crypto_forecast（backend/app/api/metrics.py）と同じ設計を踏襲する:
他のAPIで使う X-API-KEY ヘッダーではなく Authorization: Bearer で保護する
（Prometheusのスクレイプconfigが authorization.credentials でBearerトークンを
ネイティブにサポートしているため）。METRICS_API_KEY 未設定時はエンドポイント
自体を無効化する（GITHUB_TOKEN 等、他の外部連携機能と同じ opt-in パターン）。

クローラー（KEV/OSV/JVN/DEPSCAN/DEPSOPS）の実行結果は、唯一の共通記録経路である
app.crawler_logs.writer.write_crawler_log から record_crawler_run() を呼んで
Gauge を更新する。Counter ではなく Gauge にしているのは、Grafana側で「直近の
実行結果」を一目で確認したい（過去の累積ではなく最新値が欲しい）ため。
"""
import hmac

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from prometheus_client import CONTENT_TYPE_LATEST, Gauge, generate_latest

from app.core.config import settings

router = APIRouter(tags=["Observability"])

# ── クローラー実行結果（直近1回分、crawler_type ラベルで種別を区別） ──
crawler_last_run_success = Gauge(
    "crawler_last_run_success",
    "直近のクローラー実行が成功したか（1=success, 0=error）",
    ["crawler_type"],
)
crawler_last_run_timestamp_seconds = Gauge(
    "crawler_last_run_timestamp_seconds",
    "直近のクローラー実行が完了した時刻（UNIX時間）。値の陳腐化検知に使う",
    ["crawler_type"],
)
crawler_last_run_duration_seconds = Gauge(
    "crawler_last_run_duration_seconds",
    "直近のクローラー実行にかかった時間（秒）",
    ["crawler_type"],
)
crawler_last_run_inserted = Gauge(
    "crawler_last_run_inserted",
    "直近のクローラー実行での新規挿入件数",
    ["crawler_type"],
)
crawler_last_run_updated = Gauge(
    "crawler_last_run_updated",
    "直近のクローラー実行での更新件数",
    ["crawler_type"],
)
crawler_last_run_deleted = Gauge(
    "crawler_last_run_deleted",
    "直近のクローラー実行での削除件数",
    ["crawler_type"],
)


def record_crawler_run(
    crawler_type: str,
    status: str,
    duration_seconds: float,
    inserted: int,
    updated: int,
    deleted: int,
    finished_at_timestamp: float,
) -> None:
    """クローラー実行結果をPrometheusのGaugeへ反映する。

    write_crawler_log() の DB 書き込みとは独立して呼ぶため、
    この関数自体は例外を送出しない（呼び出し側で try/except する必要はない設計）。
    """
    crawler_last_run_success.labels(crawler_type=crawler_type).set(
        1 if status == "success" else 0
    )
    crawler_last_run_timestamp_seconds.labels(crawler_type=crawler_type).set(
        finished_at_timestamp
    )
    crawler_last_run_duration_seconds.labels(crawler_type=crawler_type).set(duration_seconds)
    crawler_last_run_inserted.labels(crawler_type=crawler_type).set(inserted)
    crawler_last_run_updated.labels(crawler_type=crawler_type).set(updated)
    crawler_last_run_deleted.labels(crawler_type=crawler_type).set(deleted)


def _verify_metrics_api_key(authorization: str | None = Header(default=None)) -> None:
    if not settings.METRICS_API_KEY:
        raise HTTPException(status_code=503, detail="Metrics endpoint is not configured")
    expected = f"Bearer {settings.METRICS_API_KEY}"
    # タイミング攻撃を避けるため定数時間比較を使う（他のAPIキー比較と同じ作法）
    if not authorization or not hmac.compare_digest(authorization, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing credentials")


@router.get("/metrics")
def get_metrics(_: None = Depends(_verify_metrics_api_key)) -> Response:
    """Prometheus形式でメトリクスを公開する（deploy/prometheus.ymlのスクレイプ対象）。"""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
