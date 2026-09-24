"""Slack 通知モジュールのテスト。

外部 Webhook への HTTP 通信はモックし、送信ロジックのみを検証する。
Issue #227 以降、送信先は `recipients` 引数で明示指定するのが基本（省略時は
DBから動的解決するため、その経路は `_resolve_recipients` 専用テストで検証する）。
"""
from unittest.mock import MagicMock, patch

import httpx

from app.core.notifications import (
    _resolve_recipients,
    _sanitize_error,
    is_valid_slack_webhook_url,
    notify_error,
    notify_success,
    send_test_notification,
)

_TEST_URL = "https://hooks.slack.com/services/test"


def test_notify_skips_when_no_recipients():
    """送信先が無い場合は送信しない。"""
    with patch("app.core.notifications._send_slack") as mock_send:
        notify_success("KEV", inserted=5, updated=2, recipients=[])
        mock_send.assert_not_called()


def test_notify_skips_when_no_changes():
    """新規追加・更新・削除がすべて 0 件の場合は送信しない。"""
    with patch("app.core.notifications._send_slack") as mock_send:
        notify_success("KEV", inserted=0, updated=0, recipients=[_TEST_URL])
        mock_send.assert_not_called()


def test_notify_sends_when_inserted():
    """新規追加がある場合は Slack に送信し、件数が含まれること。"""
    with patch("app.core.notifications._send_slack") as mock_send:
        notify_success("KEV", inserted=10, updated=1, recipients=[_TEST_URL])
        mock_send.assert_called_once()
        msg, url = mock_send.call_args[0]
        assert "10" in msg
        assert url == _TEST_URL


def test_notify_sends_to_each_recipient():
    """複数の送信先が指定された場合、全員分送信すること。"""
    other_url = "https://hooks.slack.com/services/other"
    with patch("app.core.notifications._send_slack") as mock_send:
        notify_success("KEV", inserted=1, updated=0, recipients=[_TEST_URL, other_url])
        assert mock_send.call_count == 2
        sent_urls = {call.args[1] for call in mock_send.call_args_list}
        assert sent_urls == {_TEST_URL, other_url}


def test_notify_sends_when_updated_only():
    """新規追加が 0 件でも更新がある場合は Slack に送信する。"""
    with patch("app.core.notifications._send_slack") as mock_send:
        notify_success("KEV", inserted=0, updated=5, recipients=[_TEST_URL])
        mock_send.assert_called_once()
        msg = mock_send.call_args[0][0]
        assert "5" in msg


def test_notify_sends_when_only_deleted():
    """削除のみの場合でも Slack に送信し、削除件数が含まれること。"""
    with patch("app.core.notifications._send_slack") as mock_send:
        notify_success("OSV", inserted=0, updated=0, deleted=5, recipients=[_TEST_URL])
        mock_send.assert_called_once()
        msg = mock_send.call_args[0][0]
        assert "削除: 5 件" in msg


def test_notify_message_uses_crawler_label():
    """crawler_type ごとのラベル・絵文字がメッセージに反映されること。"""
    with patch("app.core.notifications._send_slack") as mock_send:
        notify_success("JVN", inserted=7, updated=3, recipients=[_TEST_URL])
        msg = mock_send.call_args[0][0]
        assert "JVN 脆弱性データ" in msg
        assert "7" in msg
        assert "3" in msg


def test_notify_unknown_crawler_type_falls_back_to_generic_label():
    """未知の crawler_type でも汎用ラベルで送信されること（KeyError にならない）。"""
    with patch("app.core.notifications._send_slack") as mock_send:
        notify_success("UNKNOWN", inserted=1, updated=0, recipients=[_TEST_URL])
        mock_send.assert_called_once()


def test_notify_error_sends_message():
    """エラー通知が正しく送信される。"""
    with patch("app.core.notifications._send_slack") as mock_send:
        notify_error("KEV", "Connection timeout", recipients=[_TEST_URL])
        mock_send.assert_called_once()
        msg = mock_send.call_args[0][0]
        assert "Connection timeout" in msg


def test_notify_error_skips_without_recipients():
    """送信先が無い場合はエラー通知もスキップ。"""
    with patch("app.core.notifications._send_slack") as mock_send:
        notify_error("KEV", "some error", recipients=[])
        mock_send.assert_not_called()


def test_send_slack_success():
    """正常な Webhook 送信が成功する。"""
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()

    with patch("app.core.notifications.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.post.return_value = mock_resp
        notify_success("KEV", inserted=3, updated=0, recipients=[_TEST_URL])

    mock_client_cls.return_value.__enter__.return_value.post.assert_called_once()


def test_send_slack_http_error_does_not_raise():
    """Webhook 送信が HTTP エラーでも例外を外に伝播させない。"""
    with patch("app.core.notifications.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.post.side_effect = (
            httpx.ConnectError("connection refused")
        )
        # 例外が外に漏れないことを確認
        notify_success("KEV", inserted=1, updated=0, recipients=[_TEST_URL])


# ── _resolve_recipients テスト（DB解決の経路） ──────────────────────


def test_resolve_recipients_global_crawler_broadcasts_to_all(db_session):
    """KEV等グローバルなクローラー種別は、通知有効な全登録ユーザーへ送る。"""
    from app.auth.account_store import set_slack_webhook, upsert_user_token

    for username in ("alice", "bob"):
        upsert_user_token(db_session, username, "dummy-token")
        set_slack_webhook(db_session, username, f"https://hooks.slack.com/services/{username}")

    recipients = _resolve_recipients("KEV")
    assert set(recipients) == {
        "https://hooks.slack.com/services/alice",
        "https://hooks.slack.com/services/bob",
    }


def test_resolve_recipients_repo_scoped_crawler_uses_github_username_only(
    db_session, monkeypatch,
):
    """DEPSCAN等は GITHUB_USERNAME 自身の登録Webhookにのみ送る。"""
    from app.auth.account_store import set_slack_webhook, upsert_user_token

    monkeypatch.setattr("app.core.notifications.settings.GITHUB_USERNAME", "baby-feelings")
    upsert_user_token(db_session, "baby-feelings", "dummy-token")
    set_slack_webhook(db_session, "baby-feelings", "https://hooks.slack.com/services/owner")
    upsert_user_token(db_session, "other-user", "dummy-token")
    set_slack_webhook(db_session, "other-user", "https://hooks.slack.com/services/other")

    recipients = _resolve_recipients("DEPSCAN")
    assert recipients == ["https://hooks.slack.com/services/owner"]


# ── Webhook登録バリデーション・テスト送信 ────────────────────────────


def test_is_valid_slack_webhook_url_accepts_official_domain():
    assert is_valid_slack_webhook_url("https://hooks.slack.com/services/AAA/BBB/CCC")


def test_is_valid_slack_webhook_url_rejects_other_domain():
    assert not is_valid_slack_webhook_url("https://evil.example.com/services/AAA")


def test_send_test_notification_returns_true_on_success():
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    with patch("app.core.notifications.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.post.return_value = mock_resp
        assert send_test_notification(_TEST_URL, "alice") is True


def test_send_test_notification_returns_false_on_failure():
    with patch("app.core.notifications.httpx.Client") as mock_client_cls:
        mock_client_cls.return_value.__enter__.return_value.post.side_effect = (
            httpx.ConnectError("connection refused")
        )
        assert send_test_notification(_TEST_URL, "alice") is False


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
