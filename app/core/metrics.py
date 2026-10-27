"""運用監視のメトリクスエンドポイント（Prometheus形式）。

crypto_forecast（backend/app/api/metrics.py）と同じ設計を踏襲する:
他のAPIで使う X-API-KEY ヘッダーではなく Authorization: Bearer で保護する
（Prometheusのスクレイプconfigが authorization.credentials でBearerトークンを
ネイティブにサポートしているため）。METRICS_API_KEY 未設定時はエンドポイント
自体を無効化する（GITHUB_TOKEN 等、他の外部連携機能と同じ opt-in パターン）。

クローラーの実行結果・未解決の脆弱性の件数など、各ドメインの状態を表す指標は、DB から求めて
このエンドポイントに載せる（`app.jobs.domain_metrics`。core は個別のドメインを知らない方針のため、
ドメインを束ねる jobs 側に置いている）。メモリ上の Gauge を更新する方式にしていた頃は、
API の再起動（デプロイ）のたびに消え、次のクロールまで Grafana のパネルが空になっていた。
"""
import hmac

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.core.config import settings

router = APIRouter(tags=["Observability"])


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
