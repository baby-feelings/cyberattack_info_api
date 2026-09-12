"""外部API呼び出し共通のリトライ・指数バックオフラッパー（Issue #130）。

CISA KEVフィード・OSV API・MyJVN API・GitHub APIへの呼び出しは一時的な障害
（レート制限・5xxエラー・接続断）で失敗することがある。これらのみをリトライ
対象とし、認証エラー・権限不足等の恒久的なエラー（401/403〈レート制限由来を
除く〉/404等）は即座に呼び出し元へ伝播させる（無駄なリトライで失敗までの
時間を延ばさないため）。
"""
import logging
import time
from collections.abc import Callable

import httpx
from prometheus_client import Counter

logger = logging.getLogger(__name__)

# 一時的な障害を示すステータスコード（無条件でリトライ対象）
_RETRIABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})

# リトライ発生回数（Grafanaでの可視化用、Issue #130）。prometheus_clientのグローバル
# レジストリに登録され、app.core.metricsの/metricsエンドポイントから自動的に公開される
# （明示的な結線コードは不要）。reason: "rate_limited"（429・レート制限由来の403）/
# "transient_error"（5xx・接続断）
external_api_retry_total = Counter(
    "external_api_retry_total",
    "外部API呼び出しが一時的エラー・レート制限でリトライされた回数",
    ["reason"],
)

# レート制限超過時にAPIが待機時間の目安を返さなかった場合の待機上限（秒）。
# GitHubのプライマリレート制限（1時間単位でリセット）をそのまま待つと
# クロール全体が長時間ブロックされるため、上限でキャップする
_MAX_RATE_LIMIT_WAIT_SECONDS = 300.0


def _is_rate_limited_403(response: httpx.Response) -> bool:
    """403がレート制限由来かを判定する。

    GitHub APIの403は権限不足（トークンスコープ不足）でも返るため、
    レート制限に起因すると判定できる場合（残数0またはRetry-Afterヘッダーあり）
    のみリトライ対象とする。権限不足の403をリトライしても無駄なため区別する。
    """
    return (
        response.headers.get("X-RateLimit-Remaining") == "0"
        or "Retry-After" in response.headers
    )


def _is_retriable(response: httpx.Response) -> bool:
    if response.status_code in _RETRIABLE_STATUS_CODES:
        return True
    if response.status_code == 403:
        return _is_rate_limited_403(response)
    return False


def _retry_delay(response: httpx.Response, attempt: int, base_delay: float) -> float:
    """次回リトライまでの待機秒数を決定する。

    優先順位: Retry-Afterヘッダー（429・GitHub二次レート制限） >
    X-RateLimit-Reset（GitHubプライマリレート制限、上限でキャップ） >
    指数バックオフ（base_delay * 2^attempt）。
    """
    retry_after = response.headers.get("Retry-After")
    if retry_after is not None:
        try:
            return max(0.0, float(retry_after))
        except ValueError:
            pass

    if response.headers.get("X-RateLimit-Remaining") == "0":
        reset = response.headers.get("X-RateLimit-Reset")
        if reset is not None:
            try:
                wait = float(reset) - time.time()
                if wait > 0:
                    return min(wait, _MAX_RATE_LIMIT_WAIT_SECONDS)
            except ValueError:
                pass

    return base_delay * (2 ** attempt)


def request_with_retry(
    request_func: Callable[[], httpx.Response],
    *,
    max_attempts: int = 3,
    base_delay: float = 1.0,
) -> httpx.Response:
    """外部API呼び出しを指数バックオフ付きでリトライする。

    Args:
        request_func: 実際にHTTPリクエストを実行し `httpx.Response` を返す
            引数なしの関数（例: `lambda: client.get(url)`）。呼び出しのたびに
            新しいリクエストを送るため、冪等なメソッド（GET/PUT等）での
            使用を前提とする
        max_attempts: 最大試行回数（初回含む）
        base_delay: 指数バックオフの基準秒数（`base_delay * 2^attempt`）

    Returns:
        成功した `httpx.Response`（呼び出し前に `raise_for_status()` 済み）

    Raises:
        httpx.HTTPStatusError: 最終試行まで一時的エラーが続いた場合、または
            リトライ対象外のステータスコード（401/404等）の場合は即座に送出
        httpx.TransportError: 最終試行まで接続エラーが続いた場合
    """
    last_exc: httpx.HTTPError | None = None

    for attempt in range(max_attempts):
        try:
            response = request_func()
            response.raise_for_status()
            return response
        except httpx.HTTPStatusError as exc:
            if not _is_retriable(exc.response):
                raise
            last_exc = exc
            delay = _retry_delay(exc.response, attempt, base_delay)
            reason = "rate_limited" if exc.response.status_code in (429, 403) else "transient_error"
        except httpx.TransportError as exc:
            last_exc = exc
            delay = base_delay * (2 ** attempt)
            reason = "transient_error"

        external_api_retry_total.labels(reason=reason).inc()

        if attempt == max_attempts - 1:
            break
        logger.warning(
            "Retrying request after transient error (attempt %d/%d, waiting %.1fs): %s",
            attempt + 1, max_attempts, delay, last_exc,
        )
        time.sleep(delay)

    assert last_exc is not None  # ループを抜けるのは必ず例外発生後のため
    raise last_exc
