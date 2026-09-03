"""Slack 通知モジュールのテスト。

外部 Webhook への HTTP 通信はモックし、送信ロジックのみを検証する。
"""
from unittest.mock import MagicMock, patch

import httpx

from app.core.notifications import _sanitize_error, notify_error, notify_success


def test_notify_skips_when_no_webhook(monkeypatch):
    """SLACK_WEBHOOK_URL が未設定の場合は送信しない。"""
    monkeypatch.setattr("app.core.notifications.settings.SLACK_WEBHOOK_URL", "")
    with patch("app.core.notifications._send_slack") as mock_send:
        notify_success("KEV", inserted=5, updated=2)
        mock_send.assert_not_called()


def test_notify_skips_when_no_changes(monkeypatch):
    """新規追加・更新・削除がすべて 0 件の場合は送信しない。"""
    monkeypatch.setattr(
        "app.core.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"
    )
    with patch("app.core.notifications._send_slack") as mock_send:
        notify_success("KEV", inserted=0, updated=0)
        mock_send.assert_not_called()


def test_notify_sends_when_inserted(monkeypatch):
    """新規追加がある場合は Slack に送信し、件数が含まれること。"""
    monkeypatch.setattr(
        "app.core.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"
    )
    with patch("app.core.notifications._send_slack") as mock_send:
        notify_success("KEV", inserted=10, updated=1)
        mock_send.assert_called_once()
        # メッセージに件数が含まれることを確認
        msg = mock_send.call_args[0][0]
        assert "10" in msg


def test_notify_sends_when_updated_only(monkeypatch):
    """新規追加が 0 件でも更新がある場合は Slack に送信する。"""
    monkeypatch.setattr(
        "app.core.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"
    )
    with patch("app.core.notifications._send_slack") as mock_send:
        notify_success("KEV", inserted=0, updated=5)
        mock_send.assert_called_once()
        msg = mock_send.call_args[0][0]
        assert "5" in msg


def test_notify_sends_when_only_deleted(monkeypatch):
    """削除のみの場合でも Slack に送信し、削除件数が含まれること。"""
    monkeypatch.setattr(
        "app.core.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"
    )
    with patch("app.core.notifications._send_slack") as mock_send:
        notify_success("OSV", inserted=0, updated=0, deleted=5)
        mock_send.assert_called_once()
        msg = mock_send.call_args[0][0]
        assert "削除: 5 件" in msg


def test_notify_message_uses_crawler_label(monkeypatch):
    """crawler_type ごとのラベル・絵文字がメッセージに反映されること。"""
    monkeypatch.setattr(
        "app.core.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"
    )
    with patch("app.core.notifications._send_slack") as mock_send:
        notify_success("JVN", inserted=7, updated=3)
        msg = mock_send.call_args[0][0]
        assert "JVN 脆弱性データ" in msg
        assert "7" in msg
        assert "3" in msg


def test_notify_unknown_crawler_type_falls_back_to_generic_label(monkeypatch):
    """未知の crawler_type でも汎用ラベルで送信されること（KeyError にならない）。"""
    monkeypatch.setattr(
        "app.core.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"
    )
    with patch("app.core.notifications._send_slack") as mock_send:
        notify_success("UNKNOWN", inserted=1, updated=0)
        mock_send.assert_called_once()


def test_notify_error_sends_message(monkeypatch):
    """エラー通知が正しく送信される。"""
    monkeypatch.setattr(
        "app.core.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"
    )
    with patch("app.core.notifications._send_slack") as mock_send:
        notify_error("KEV", "Connection timeout")
        mock_send.assert_called_once()
        msg = mock_send.call_args[0][0]
        assert "Connection timeout" in msg


def test_notify_error_skips_without_webhook(monkeypatch):
    """Webhook URL 未設定時はエラー通知もスキップ。"""
    monkeypatch.setattr("app.core.notifications.settings.SLACK_WEBHOOK_URL", "")
    with patch("app.core.notifications._send_slack") as mock_send:
        notify_error("KEV", "some error")
        mock_send.assert_not_called()


def test_send_slack_success(monkeypatch):
    """正常な Webhook 送信が成功する。"""
    monkeypatch.setattr(
        "app.core.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"
    )
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()

    with patch("app.core.notifications.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.post.return_value = mock_resp
        notify_success("KEV", inserted=3, updated=0)

    mock_client_cls.return_value.__enter__.return_value.post.assert_called_once()


def test_send_slack_http_error_does_not_raise(monkeypatch):
    """Webhook 送信が HTTP エラーでも例外を外に伝播させない。"""
    monkeypatch.setattr(
        "app.core.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/test"
    )
    with patch("app.core.notifications.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.post.side_effect = (
            httpx.ConnectError("connection refused")
        )
        # 例外が外に漏れないことを確認
        notify_success("KEV", inserted=1, updated=0)


# ── _sanitize_error テスト ────────────────────────────────────────


def test_sanitize_error_masks_connection_string():
    """接続文字列がマスクされること。"""
    error = "connection failed: postgresql://user:pass@host:5432/db timeout"
    result = _sanitize_error(error)
    assert "postgresql://" not in result
    assert "***masked-url***" in result
    assert "timeout" in result


def test_sanitize_error_truncates_long_message():
    """200 文字を超えるメッセージが切り詰められること。"""
    error = "x" * 300
    result = _sanitize_error(error)
    assert len(result) == 203  # 200 + "..."
    assert result.endswith("...")


def test_sanitize_error_passes_short_message():
    """短いメッセージはそのまま返すこと。"""
    error = "simple error"
    assert _sanitize_error(error) == "simple error"
