"""MCP 接続の認証情報が発行されたときの事後通知（本人の Webhook にだけ送る）のテスト。"""
from unittest.mock import patch

from app.core.notifications.mcp_token import (
    notify_mcp_token_issued,
    notify_oauth_connection_granted,
)

_HOOK = "https://hooks.slack.com/services/T000/B000/XXXX"
_SEND = "app.core.notifications.slack.send_slack"


def _sent(mock) -> tuple[str, str]:
    """send_slack に渡された (本文, 送信先URL) を返す。"""
    (message, url), _ = mock.call_args
    return message, url


class TestNotifyMcpTokenIssued:
    def test_sends_only_to_the_given_webhook_with_expiry(self):
        with patch(_SEND, return_value=True) as send:
            assert notify_mcp_token_issued(_HOOK, "2026-11-12") is True

        message, url = _sent(send)
        assert url == _HOOK
        send.assert_called_once()
        assert "MCPトークン" in message and "2026-11-12" in message
        assert "心当たりがない場合" in message

    def test_returns_false_when_sending_fails(self):
        with patch(_SEND, return_value=False):
            assert notify_mcp_token_issued(_HOOK, "2026-11-12") is False


class TestNotifyOauthConnectionGranted:
    def test_includes_the_client_name_as_self_declared(self):
        with patch(_SEND, return_value=True) as send:
            assert notify_oauth_connection_granted(_HOOK, "Claude Code") is True

        message, url = _sent(send)
        assert url == _HOOK
        assert "OAuth接続" in message and "Claude Code" in message and "自己申告" in message

    def test_neutralizes_slack_markup_and_newlines_in_the_client_name(self):
        # クライアント名は登録時の自己申告。メンション・リンク・書式・改行を無効にしてから載せる
        evil = "<!channel> *bold* `code`\n>fake line <https://evil.example|click>"
        with patch(_SEND, return_value=True) as send:
            notify_oauth_connection_granted(_HOOK, evil)

        message, _ = _sent(send)
        name_line = next(line for line in message.splitlines() if "クライアント名" in line)
        for ch in "<>&`*_~|":
            assert ch not in name_line.replace(">種別", "")  # 先頭の引用記号以外には出ない
        assert "\n" not in name_line

    def test_truncates_a_long_client_name(self):
        with patch(_SEND, return_value=True) as send:
            notify_oauth_connection_granted(_HOOK, "a" * 500)

        message, _ = _sent(send)
        assert "a" * 51 not in message
        assert "a" * 50 in message

    def test_falls_back_when_the_client_name_is_empty(self):
        with patch(_SEND, return_value=True) as send:
            notify_oauth_connection_granted(_HOOK, "")

        assert "（名前なし）" in _sent(send)[0]
