"""MCP トークンの期限前通知・発行時の事後通知（そのユーザー本人の Webhook にだけ送る）。"""
import re

from app.core.notifications.base import Notifier
from app.core.notifications.slack import DASHBOARD_URL


class McpTokenExpiryNotifier(Notifier):
    """期限が近い MCP トークンがあることを、指定した Webhook にだけ通知する。

    トークン本体は載せない。再発行の手順だけを案内する。送信先は必ず明示指定する
    （ユーザー本人の Webhook。既定の送信先は持たない）。
    """

    def __init__(self, expiry_dates: list[str], webhook_url: str) -> None:
        super().__init__([webhook_url])
        self._expiry_dates = expiry_dates

    def has_content(self) -> bool:
        return True

    def default_recipients(self) -> list[str]:
        return []  # 常に明示指定される

    def build_message(self) -> str:
        lines = "\n".join(f">• 有効期限 {d}" for d in sorted(self._expiry_dates))
        return (
            ":hourglass_flowing_sand: *MCPトークンの期限が近づいています*"
            f"（{len(self._expiry_dates)}件）\n"
            f"{lines}\n"
            ">期限が切れると、AIエージェントからのMCP接続が401になります。"
            "ダッシュボードの「設定」→「MCPトークン」で再発行し、登録し直してください。\n"
            f">詳細: {DASHBOARD_URL}"
        )


def notify_mcp_token_expiry(webhook_url: str, expiry_dates: list[str]) -> bool:
    """期限が近い MCP トークンを、そのユーザー本人の Webhook にだけ通知する。

    送信に成功したかを返す（呼び出し側は成功したときだけ「通知済み」にする）。

    Args:
        expiry_dates: 期限が近いトークンの有効期限（YYYY-MM-DD）の一覧。
    """
    return McpTokenExpiryNotifier(expiry_dates, webhook_url).send()


# Slack のメッセージに載せる、自己申告の文字列（OAuth クライアント名）の最大長
_MAX_NAME_CHARS = 50


def _plain(text: str) -> str:
    """外部から来た文字列を、Slack の書式・リンク・メンションに化けない形にして短くする。"""
    return re.sub(r"[\r\n<>&`*_~|]", " ", text).strip()[:_MAX_NAME_CHARS]


class McpCredentialIssuedNotifier(Notifier):
    """MCP 接続の認証情報（MCP トークン・OAuth 接続）が新しく発行されたことを、本人に事後通知する。

    IPA「安全なウェブサイトの作り方」6-(ii)（重要な操作を行った際に、その旨を本人へ自動通知する）
    に沿った、第三者による不正な発行に気づくための保険的対策。トークン本体は載せない。
    送信先は必ず明示指定する（ユーザー本人の Webhook。既定の送信先は持たない）。
    """

    def __init__(self, summary: str, webhook_url: str) -> None:
        super().__init__([webhook_url])
        self._summary = summary

    def has_content(self) -> bool:
        return True

    def default_recipients(self) -> list[str]:
        return []  # 常に明示指定される

    def build_message(self) -> str:
        return (
            ":key: *MCP接続の認証情報が発行されました*\n"
            f">{self._summary}\n"
            ">心当たりがない場合は、ダッシュボードの「設定」から、該当するトークン・接続を"
            "すぐに失効（解除）してください。\n"
            f">詳細: {DASHBOARD_URL}"
        )


def notify_mcp_token_issued(webhook_url: str, expires_on: str) -> bool:
    """MCP トークンの発行を、本人の Webhook にだけ通知する（expires_on: YYYY-MM-DD）。"""
    return McpCredentialIssuedNotifier(
        f"種別: MCPトークン（有効期限 {_plain(expires_on)}）", webhook_url,
    ).send()


def notify_oauth_connection_granted(webhook_url: str, client_name: str) -> bool:
    """OAuth でクライアントの接続を許可したことを、そのユーザー本人の Webhook にだけ通知する。

    クライアント名は登録時の自己申告（未確認）のため、書式を無効にして短くしてから載せる。
    """
    name = _plain(client_name) or "（名前なし）"
    return McpCredentialIssuedNotifier(
        f"種別: OAuth接続（クライアント名: {name}。自己申告）", webhook_url,
    ).send()

