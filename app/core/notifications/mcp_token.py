"""MCP トークンの期限前通知（そのユーザー本人の Webhook にだけ送る）。"""
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
