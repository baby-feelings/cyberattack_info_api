"""app.core.notifications.slack / webhook_test（送信・URL 検証・テスト送信）のテスト。"""
from unittest.mock import MagicMock, patch

import httpx

from app.core.notifications.slack import is_valid_slack_webhook_url, send_slack
from app.core.notifications.webhook_test import send_test_notification

_TEST_URL = "https://hooks.slack.com/services/test"


def test_send_slack_success():
    """正常な Webhook 送信が成功する。"""
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()

    with patch("httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.post.return_value = mock_resp
        assert send_slack("msg", _TEST_URL) is True

    mock_client_cls.return_value.__enter__.return_value.post.assert_called_once()


def test_send_slack_http_error_does_not_raise():
    """Webhook 送信が HTTP エラーでも例外を外に伝播させない。"""
    with patch("httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.post.side_effect = (
            httpx.ConnectError("connection refused")
        )
        # 例外が外に漏れないことを確認
        assert send_slack("msg", _TEST_URL) is False


def test_is_valid_slack_webhook_url_accepts_official_domain():
    assert is_valid_slack_webhook_url("https://hooks.slack.com/services/AAA/BBB/CCC")


def test_is_valid_slack_webhook_url_rejects_other_domain():
    assert not is_valid_slack_webhook_url("https://evil.example.com/services/AAA")


def test_send_test_notification_returns_true_on_success():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    with patch("httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.post.return_value = mock_resp
        assert send_test_notification(_TEST_URL, "alice") is True


def test_send_test_notification_returns_false_on_failure():
    with patch("httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.post.side_effect = (
            httpx.ConnectError("connection refused")
        )
        assert send_test_notification(_TEST_URL, "alice") is False
