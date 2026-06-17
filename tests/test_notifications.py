"""Slack 通知モジュールのテスト。

外部 Webhook への HTTP 通信はモックし、送信ロジックのみを検証する。
"""
from unittest.mock import MagicMock, patch

import httpx

from app.notifications import (
    notify_crawl_error,
    notify_new_vulnerabilities,
    notify_osv_crawl_error,
    notify_osv_new_vulnerabilities,
)


def test_notify_skips_when_no_webhook(monkeypatch):
    """SLACK_WEBHOOK_URL が未設定の場合は送信しない。"""
    monkeypatch.setattr("app.notifications.settings.SLACK_WEBHOOK_URL", "")
    with patch("app.notifications._send_slack") as mock_send:
        notify_new_vulnerabilities(inserted=5, updated=2)
        mock_send.assert_not_called()


def test_notify_skips_when_no_changes(monkeypatch):
    """新規追加・更新ともに 0 件の場合は送信しない。"""
    monkeypatch.setattr(
        "app.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"
    )
    with patch("app.notifications._send_slack") as mock_send:
        notify_new_vulnerabilities(inserted=0, updated=0)
        mock_send.assert_not_called()


def test_notify_sends_when_inserted(monkeypatch):
    """新規追加がある場合は Slack に送信し、件数が含まれること。"""
    monkeypatch.setattr(
        "app.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"
    )
    with patch("app.notifications._send_slack") as mock_send:
        notify_new_vulnerabilities(inserted=10, updated=1)
        mock_send.assert_called_once()
        # メッセージに件数が含まれることを確認
        msg = mock_send.call_args[0][0]
        assert "10" in msg


def test_notify_sends_when_updated_only(monkeypatch):
    """新規追加が 0 件でも更新がある場合は Slack に送信する。"""
    monkeypatch.setattr(
        "app.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"
    )
    with patch("app.notifications._send_slack") as mock_send:
        notify_new_vulnerabilities(inserted=0, updated=5)
        mock_send.assert_called_once()
        msg = mock_send.call_args[0][0]
        assert "5" in msg


def test_notify_crawl_error_sends_message(monkeypatch):
    """エラー通知が正しく送信される。"""
    monkeypatch.setattr(
        "app.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"
    )
    with patch("app.notifications._send_slack") as mock_send:
        notify_crawl_error("Connection timeout")
        mock_send.assert_called_once()
        msg = mock_send.call_args[0][0]
        assert "Connection timeout" in msg


def test_notify_crawl_error_skips_without_webhook(monkeypatch):
    """Webhook URL 未設定時はエラー通知もスキップ。"""
    monkeypatch.setattr("app.notifications.settings.SLACK_WEBHOOK_URL", "")
    with patch("app.notifications._send_slack") as mock_send:
        notify_crawl_error("some error")
        mock_send.assert_not_called()


def test_send_slack_success(monkeypatch):
    """正常な Webhook 送信が成功する。"""
    monkeypatch.setattr(
        "app.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"
    )
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()

    with patch("app.notifications.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.post.return_value = mock_resp
        notify_new_vulnerabilities(inserted=3, updated=0)

    mock_client_cls.return_value.__enter__.return_value.post.assert_called_once()


def test_send_slack_http_error_does_not_raise(monkeypatch):
    """Webhook 送信が HTTP エラーでも例外を外に伝播させない。"""
    monkeypatch.setattr(
        "app.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"
    )
    with patch("app.notifications.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.post.side_effect = (
            httpx.ConnectError("connection refused")
        )
        # 例外が外に漏れないことを確認
        notify_new_vulnerabilities(inserted=1, updated=0)


# ──────────────────────────────────────────────────────────────
# OSV 通知
# ──────────────────────────────────────────────────────────────


def test_osv_notify_skips_when_no_webhook(monkeypatch):
    """SLACK_WEBHOOK_URL 未設定時は OSV 通知を送信しない。"""
    monkeypatch.setattr("app.notifications.settings.SLACK_WEBHOOK_URL", "")
    with patch("app.notifications._send_slack") as mock_send:
        notify_osv_new_vulnerabilities(inserted=5, updated=2, deleted=10)
        mock_send.assert_not_called()


def test_osv_notify_skips_when_no_changes(monkeypatch):
    """新規・更新が 0 件の場合は OSV 通知を送信しない。"""
    monkeypatch.setattr(
        "app.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"
    )
    with patch("app.notifications._send_slack") as mock_send:
        notify_osv_new_vulnerabilities(inserted=0, updated=0, deleted=5)
        mock_send.assert_not_called()


def test_osv_notify_sends_when_inserted(monkeypatch):
    """OSV 新規追加があれば Slack に送信し、件数が含まれること。"""
    monkeypatch.setattr(
        "app.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"
    )
    with patch("app.notifications._send_slack") as mock_send:
        notify_osv_new_vulnerabilities(inserted=8, updated=3, deleted=2)
        mock_send.assert_called_once()
        msg = mock_send.call_args[0][0]
        assert "8" in msg
        assert "3" in msg
        assert "2" in msg


def test_osv_notify_sends_when_updated_only(monkeypatch):
    """OSV 更新のみの場合も送信されること。"""
    monkeypatch.setattr(
        "app.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"
    )
    with patch("app.notifications._send_slack") as mock_send:
        notify_osv_new_vulnerabilities(inserted=0, updated=5, deleted=0)
        mock_send.assert_called_once()


def test_osv_crawl_error_sends_message(monkeypatch):
    """OSV エラー通知が正しく送信される。"""
    monkeypatch.setattr(
        "app.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"
    )
    with patch("app.notifications._send_slack") as mock_send:
        notify_osv_crawl_error("OSV API timeout")
        mock_send.assert_called_once()
        msg = mock_send.call_args[0][0]
        assert "OSV API timeout" in msg


def test_osv_crawl_error_skips_without_webhook(monkeypatch):
    """Webhook URL 未設定時は OSV エラー通知もスキップ。"""
    monkeypatch.setattr("app.notifications.settings.SLACK_WEBHOOK_URL", "")
    with patch("app.notifications._send_slack") as mock_send:
        notify_osv_crawl_error("some error")
        mock_send.assert_not_called()
