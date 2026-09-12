"""app.core.retry（外部API呼び出し共通のリトライ・指数バックオフ）のテスト。"""
from unittest.mock import MagicMock, patch

import httpx
import pytest

from app.core.retry import external_api_retry_total, request_with_retry


def _response(status_code: int, headers: dict[str, str] | None = None) -> httpx.Response:
    request = httpx.Request("GET", "https://example.com")
    return httpx.Response(status_code, headers=headers or {}, request=request)


class TestRequestWithRetrySuccess:
    def test_returns_response_on_first_success(self):
        request_func = MagicMock(return_value=_response(200))
        result = request_with_retry(request_func)
        assert result.status_code == 200
        request_func.assert_called_once()

    def test_does_not_sleep_on_first_success(self):
        request_func = MagicMock(return_value=_response(200))
        with patch("app.core.retry.time.sleep") as mock_sleep:
            request_with_retry(request_func)
        mock_sleep.assert_not_called()


class TestRequestWithRetryTransientErrors:
    def test_retries_on_503_then_succeeds(self):
        request_func = MagicMock(side_effect=[_response(503), _response(200)])
        with patch("app.core.retry.time.sleep") as mock_sleep:
            result = request_with_retry(request_func, max_attempts=3, base_delay=1.0)
        assert result.status_code == 200
        assert request_func.call_count == 2
        mock_sleep.assert_called_once_with(1.0)

    def test_exponential_backoff_delays(self):
        request_func = MagicMock(
            side_effect=[_response(500), _response(500), _response(200)],
        )
        with patch("app.core.retry.time.sleep") as mock_sleep:
            request_with_retry(request_func, max_attempts=3, base_delay=2.0)
        assert mock_sleep.call_args_list == [((2.0,),), ((4.0,),)]

    def test_raises_after_exhausting_max_attempts(self):
        request_func = MagicMock(return_value=_response(502))
        with patch("app.core.retry.time.sleep"):
            with pytest.raises(httpx.HTTPStatusError):
                request_with_retry(request_func, max_attempts=3)
        assert request_func.call_count == 3

    def test_retries_on_transport_error(self):
        request_func = MagicMock(
            side_effect=[httpx.ConnectError("boom", request=httpx.Request("GET", "https://x")),
                         _response(200)],
        )
        with patch("app.core.retry.time.sleep"):
            result = request_with_retry(request_func, max_attempts=3)
        assert result.status_code == 200

    def test_raises_transport_error_after_exhausting_attempts(self):
        request_func = MagicMock(
            side_effect=httpx.ConnectError("boom", request=httpx.Request("GET", "https://x")),
        )
        with patch("app.core.retry.time.sleep"):
            with pytest.raises(httpx.ConnectError):
                request_with_retry(request_func, max_attempts=2)
        assert request_func.call_count == 2


class TestRequestWithRetryNonRetriableErrors:
    def test_does_not_retry_on_404(self):
        request_func = MagicMock(return_value=_response(404))
        with pytest.raises(httpx.HTTPStatusError):
            request_with_retry(request_func, max_attempts=3)
        request_func.assert_called_once()

    def test_does_not_retry_on_401(self):
        request_func = MagicMock(return_value=_response(401))
        with pytest.raises(httpx.HTTPStatusError):
            request_with_retry(request_func, max_attempts=3)
        request_func.assert_called_once()

    def test_does_not_retry_on_plain_403(self):
        """権限不足の403（レート制限ヘッダーなし）はリトライしない。"""
        request_func = MagicMock(return_value=_response(403))
        with pytest.raises(httpx.HTTPStatusError):
            request_with_retry(request_func, max_attempts=3)
        request_func.assert_called_once()


class TestRequestWithRetryRateLimit403:
    def test_retries_403_with_retry_after_header(self):
        request_func = MagicMock(
            side_effect=[_response(403, {"Retry-After": "0"}), _response(200)],
        )
        with patch("app.core.retry.time.sleep") as mock_sleep:
            result = request_with_retry(request_func, max_attempts=3)
        assert result.status_code == 200
        mock_sleep.assert_called_once_with(0.0)

    def test_retries_403_with_rate_limit_remaining_zero(self):
        request_func = MagicMock(
            side_effect=[
                _response(403, {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "0"}),
                _response(200),
            ],
        )
        with patch("app.core.retry.time.sleep"):
            result = request_with_retry(request_func, max_attempts=3)
        assert result.status_code == 200


class TestRetryMetrics:
    def test_increments_transient_error_counter(self):
        before = external_api_retry_total.labels(reason="transient_error")._value.get()
        request_func = MagicMock(side_effect=[_response(503), _response(200)])
        with patch("app.core.retry.time.sleep"):
            request_with_retry(request_func, max_attempts=3)
        after = external_api_retry_total.labels(reason="transient_error")._value.get()
        assert after == before + 1

    def test_increments_rate_limited_counter(self):
        before = external_api_retry_total.labels(reason="rate_limited")._value.get()
        request_func = MagicMock(side_effect=[_response(429), _response(200)])
        with patch("app.core.retry.time.sleep"):
            request_with_retry(request_func, max_attempts=3)
        after = external_api_retry_total.labels(reason="rate_limited")._value.get()
        assert after == before + 1

    def test_does_not_increment_on_non_retriable_error(self):
        before = external_api_retry_total.labels(reason="transient_error")._value.get()
        request_func = MagicMock(return_value=_response(404))
        with pytest.raises(httpx.HTTPStatusError):
            request_with_retry(request_func, max_attempts=3)
        after = external_api_retry_total.labels(reason="transient_error")._value.get()
        assert after == before


class TestRetryDelayCalculation:
    def test_retry_after_header_takes_priority(self):
        request_func = MagicMock(
            side_effect=[_response(429, {"Retry-After": "5"}), _response(200)],
        )
        with patch("app.core.retry.time.sleep") as mock_sleep:
            request_with_retry(request_func, max_attempts=3, base_delay=1.0)
        mock_sleep.assert_called_once_with(5.0)

    def test_rate_limit_reset_capped_at_max_wait(self):
        import time as time_module

        far_future = time_module.time() + 10_000
        headers = {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(far_future)}
        request_func = MagicMock(
            side_effect=[_response(429, headers), _response(200)],
        )
        with patch("app.core.retry.time.sleep") as mock_sleep:
            request_with_retry(request_func, max_attempts=3, base_delay=1.0)
        # 上限 (300秒) でキャップされること
        assert mock_sleep.call_args_list[0][0][0] == 300.0

    def test_invalid_rate_limit_reset_falls_back_to_exponential_backoff(self):
        headers = {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "not-a-number"}
        request_func = MagicMock(side_effect=[_response(429, headers), _response(200)])
        with patch("app.core.retry.time.sleep") as mock_sleep:
            request_with_retry(request_func, max_attempts=3, base_delay=1.0)
        mock_sleep.assert_called_once_with(1.0)

    def test_invalid_retry_after_falls_back_to_exponential_backoff(self):
        request_func = MagicMock(
            side_effect=[_response(503, {"Retry-After": "not-a-number"}), _response(200)],
        )
        with patch("app.core.retry.time.sleep") as mock_sleep:
            request_with_retry(request_func, max_attempts=3, base_delay=1.0)
        mock_sleep.assert_called_once_with(1.0)
