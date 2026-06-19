"""Slack 通知モジュール。
クローラーが脆弱性データを更新したとき、または失敗したとき Slack Webhook へ通知する。
SLACK_WEBHOOK_URL が未設定の場合は何もしない（サイレントスキップ）。
"""
import logging
import re

import httpx

from app.config import settings

logger = logging.getLogger(__name__)

_WEBHOOK_TIMEOUT = 10.0
_DASHBOARD_URL = "https://cyberattackinfoapi.vercel.app/"

# 接続文字列パターン（postgresql:// / sqlite:// 等）をマスク
_CONN_STR_RE = re.compile(r"\b\w+://[^\s]+")
_MAX_ERROR_LEN = 200

# クローラー種別ごとの表示設定
_CRAWLER_LABELS: dict[str, tuple[str, str]] = {
    "KEV": (":shield:", "CISA KEV"),
    "OSV": (":package:", "OSV 脆弱性データ"),
    "JVN": (":jigsaw:", "JVN 脆弱性データ"),
}


def _sanitize_error(error: str) -> str:
    """エラーメッセージから接続文字列をマスクし、長さを制限する。"""
    sanitized = _CONN_STR_RE.sub("***masked-url***", error)
    if len(sanitized) > _MAX_ERROR_LEN:
        sanitized = sanitized[:_MAX_ERROR_LEN] + "..."
    return sanitized


def notify_success(
    crawler_type: str,
    inserted: int,
    updated: int,
    deleted: int = 0,
) -> None:
    """クローラー成功時の Slack 通知（共通）。変化がなければ通知しない。"""
    if not settings.SLACK_WEBHOOK_URL:
        return
    if inserted == 0 and updated == 0:
        return

    emoji, label = _CRAWLER_LABELS.get(crawler_type, (":bell:", crawler_type))
    lines = [
        f"{emoji} *{label}更新通知*",
        f">新規追加: *{inserted} 件*　更新: {updated} 件"
        + (f"　削除: {deleted} 件" if deleted else ""),
        f">詳細: {_DASHBOARD_URL}",
    ]
    _send_slack("\n".join(lines))


def notify_error(crawler_type: str, error: str) -> None:
    """クローラーエラー時の Slack 通知（共通）。"""
    if not settings.SLACK_WEBHOOK_URL:
        return
    _, label = _CRAWLER_LABELS.get(crawler_type, (":bell:", crawler_type))
    _send_slack(f":warning: *{label}クローラーエラー*\n```{_sanitize_error(error)}```")


# ── 後方互換ラッパー（既存テスト・呼び出し元との互換性を維持） ──────


def notify_new_vulnerabilities(inserted: int, updated: int) -> None:
    """KEV 成功通知（後方互換）。"""
    notify_success("KEV", inserted, updated)


def notify_osv_new_vulnerabilities(inserted: int, updated: int, deleted: int) -> None:
    """OSV 成功通知（後方互換）。"""
    notify_success("OSV", inserted, updated, deleted)


def notify_jvn_new_vulnerabilities(inserted: int, updated: int) -> None:
    """JVN 成功通知（後方互換）。"""
    notify_success("JVN", inserted, updated)


def notify_crawl_error(error: str) -> None:
    """KEV エラー通知（後方互換）。"""
    notify_error("KEV", error)


def notify_osv_crawl_error(error: str) -> None:
    """OSV エラー通知（後方互換）。"""
    notify_error("OSV", error)


def notify_jvn_crawl_error(error: str) -> None:
    """JVN エラー通知（後方互換）。"""
    notify_error("JVN", error)


# ── Slack 送信 ────────────────────────────────────────────────────


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
