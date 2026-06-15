"""Slack 通知モジュール。
クローラーが新規 CVE を検出したとき Slack Webhook へメッセージを送信する。
SLACK_WEBHOOK_URL が未設定の場合は何もしない（サイレントスキップ）。
"""
import logging

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

_WEBHOOK_TIMEOUT = 10.0


def notify_new_vulnerabilities(inserted: int, updated: int) -> None:
    """新規・更新された CVE 件数を Slack に通知する。

    Args:
        inserted: 新規追加件数
        updated:  更新件数
    """
    # Webhook URL が設定されていない場合はスキップ
    if not settings.SLACK_WEBHOOK_URL:
        return

    # 新規追加がなければ通知不要
    if inserted == 0:
        return

    message = (
        f":shield: *CISA KEV 更新通知*\n"
        f">新規追加: *{inserted} 件*　更新: {updated} 件\n"
        f">詳細: https://cyberattack-info-api.onrender.com/api/vulnerabilities/recent?days=1"
    )

    _send_slack(message)


def notify_osv_new_vulnerabilities(inserted: int, updated: int, deleted: int) -> None:
    """OSV クローラーの実行結果を Slack に通知する。

    Args:
        inserted: 新規追加件数
        updated:  更新件数
        deleted:  削除件数（保持期間超過による）
    """
    if not settings.SLACK_WEBHOOK_URL:
        return

    # 変化がなければ通知不要
    if inserted == 0 and updated == 0:
        return

    message = (
        f":package: *OSV 脆弱性データ更新通知*\n"
        f">新規追加: *{inserted} 件*　更新: {updated} 件　削除: {deleted} 件\n"
        f">詳細: https://cyberattack-info-api.onrender.com/api/osv"
    )

    _send_slack(message)


def notify_osv_crawl_error(error: str) -> None:
    """OSV クローラーのエラーを Slack に通知する。

    Args:
        error: エラーメッセージ
    """
    if not settings.SLACK_WEBHOOK_URL:
        return

    message = f":warning: *OSV クローラーエラー*\n```{error}```"
    _send_slack(message)


def notify_crawl_error(error: str) -> None:
    """クローラーのエラーを Slack に通知する。

    Args:
        error: エラーメッセージ
    """
    if not settings.SLACK_WEBHOOK_URL:
        return

    message = f":warning: *CISA KEV クローラーエラー*\n```{error}```"
    _send_slack(message)


def _send_slack(message: str) -> None:
    """Slack Incoming Webhook にメッセージを POST する。
    エラー時はログに記録するだけでアプリを止めない。
    """
    try:
        with httpx.Client(timeout=_WEBHOOK_TIMEOUT) as client:
            resp = client.post(
                settings.SLACK_WEBHOOK_URL,
                json={"text": message},
            )
            resp.raise_for_status()
        logger.info("Slack notification sent successfully")
    except httpx.HTTPError as exc:
        logger.warning("Slack notification failed: %s", exc)
