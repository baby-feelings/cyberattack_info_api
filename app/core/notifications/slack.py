"""Slack Incoming Webhook への送信と、Webhook URL の検証。"""
import logging

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

_WEBHOOK_TIMEOUT = 10.0


def dashboard_link(base_url: str) -> str:
    """通知本文に載せるダッシュボードへのリンク。設定は末尾スラッシュなしで持つため、そろえる。"""
    return base_url.rstrip("/") + "/"


# 通知本文に載せるダッシュボードへのリンク（設定の `DASHBOARD_URL`）
DASHBOARD_URL = dashboard_link(settings.DASHBOARD_URL)

# Slack Incoming Webhook の正規のURLプレフィックス（登録時のバリデーション用）
SLACK_WEBHOOK_URL_PREFIX = "https://hooks.slack.com/"

# Slack Incoming Webhook の text フィールド上限（40,000文字）に対する安全マージン
_MAX_SLACK_MESSAGE_LEN = 39000


def escape_mrkdwn(text: str) -> str:
    """Slack の mrkdwn に、外部の文字列（名前・URL・メッセージ）を、そのまま埋め込まない。

    `<...>` のリンク・メンション、`&`、バッククォート（書式の終了）、改行（行の偽装）を無害にする。
    """
    cleaned = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return " ".join(cleaned.replace("`", "'").split())


def truncate_for_slack(message: str) -> str:
    """Slack の text フィールド上限を超える場合、行の途中で切らずに省略する。"""
    if len(message) <= _MAX_SLACK_MESSAGE_LEN:
        return message
    truncated = message[:_MAX_SLACK_MESSAGE_LEN]
    last_newline = truncated.rfind("\n")
    if last_newline > 0:
        truncated = truncated[:last_newline]
    return truncated + (
        "\n\n...（メッセージが長すぎるため以降省略。詳細は API / ダッシュボードを参照）"
    )


def is_valid_slack_webhook_url(url: str) -> bool:
    """登録画面での簡易フォーマットチェック（本物のSlack Webhookかどうかは
    `send_test_notification` の実際の送信結果で確認する）。
    """
    return url.startswith(SLACK_WEBHOOK_URL_PREFIX)


def send_slack(message: str, webhook_url: str) -> bool:
    """Slack Incoming Webhook にメッセージを POST する。

    エラー時はログに記録するだけでアプリを止めない（毎日クロールからの
    呼び出しでは戻り値を無視する）。テスト送信（`send_test_notification`）は
    戻り値で成否を判定する。
    """
    try:
        with httpx.Client(timeout=_WEBHOOK_TIMEOUT) as client:
            resp = client.post(webhook_url, json={"text": message})
            resp.raise_for_status()
        logger.info("Slack notification sent successfully")
        return True
    except httpx.HTTPError as exc:
        logger.warning("Slack notification failed: %s", exc)
        return False
