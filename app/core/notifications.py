"""Slack 通知モジュール。
クローラーが脆弱性データを更新したとき、または失敗したとき Slack Webhook へ通知する。
SLACK_WEBHOOK_URL が未設定の場合は何もしない（サイレントスキップ）。
"""
import logging
import re
from typing import Any

import httpx

from app.core.config import settings

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
    "DEPSCAN": (":rotating_light:", "依存ライブラリ脆弱性"),
}

# Slack 通知に含める最大リポジトリ数（メッセージ長制限のため）
_MAX_DEPSCAN_REPOS_IN_MESSAGE = 15


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
    if inserted == 0 and updated == 0 and deleted == 0:
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


def notify_depscan_crawl_error(error: str) -> None:
    """DEPSCAN エラー通知。"""
    notify_error("DEPSCAN", error)


# ── DEPSCAN 専用通知 ─────────────────────────────────────────────


def notify_dependency_findings(new_findings: list[dict[str, Any]]) -> None:
    """依存ライブラリ脆弱性の新規検知を Slack に1通のダイジェストとして通知する。
    リポジトリ別にグルーピングし、findings が空なら何もしない。

    Args:
        new_findings: DependencyFinding 相当のフィールドを持つ辞書のリスト
            （"repo_full_name"・"package_name"・"installed_version"・"severity"・
            "fixed_versions"・"osv_id" を使用。ORM セッションクローズ後の
            DetachedInstanceError を避けるため、ORM オブジェクトではなく辞書で受け取る）
    """
    if not settings.SLACK_WEBHOOK_URL or not new_findings:
        return

    emoji, label = _CRAWLER_LABELS["DEPSCAN"]
    by_repo: dict[str, list[dict[str, Any]]] = {}
    for finding in new_findings:
        by_repo.setdefault(finding["repo_full_name"], []).append(finding)

    lines = [f"{emoji} *{label}を{len(new_findings)}件検知*", ""]
    for repo in list(by_repo.keys())[:_MAX_DEPSCAN_REPOS_IN_MESSAGE]:
        lines.append(f"*{repo}*")
        for finding in by_repo[repo]:
            sev = finding.get("severity") or "UNKNOWN"
            fixed_versions = finding.get("fixed_versions") or []
            fix = ", ".join(fixed_versions) if fixed_versions else "未提供"
            lines.append(
                f"• {finding['package_name']} {finding['installed_version']} "
                f"({sev}) → 修正版: {fix} [{finding['osv_id']}]"
            )
        lines.append("")

    remaining_repos = len(by_repo) - _MAX_DEPSCAN_REPOS_IN_MESSAGE
    if remaining_repos > 0:
        lines.append(f"...他 {remaining_repos} リポジトリ")

    _send_slack("\n".join(lines).rstrip())


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
