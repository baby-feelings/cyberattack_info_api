"""Slack 通知モジュール。
クローラーが脆弱性データを更新したとき、または失敗したとき Slack Webhook へ通知する。
SLACK_WEBHOOK_URL が未設定の場合は何もしない（サイレントスキップ）。
"""
import logging
import re
from typing import Any

import httpx

from app.core.config import settings
from app.core.finding_format import format_package_lines
from app.core.types import CrawlerType

logger = logging.getLogger(__name__)

_WEBHOOK_TIMEOUT = 10.0
DASHBOARD_URL = "https://cyberattackinfoapi.vercel.app/"

# 接続文字列パターン（postgresql:// / sqlite:// 等）をマスク
_CONN_STR_RE = re.compile(r"\b\w+://[^\s]+")
_MAX_ERROR_LEN = 200

# クローラー種別ごとの表示設定
_CRAWLER_LABELS: dict[str, tuple[str, str]] = {
    "KEV": (":shield:", "CISA KEV"),
    "OSV": (":package:", "OSV 脆弱性データ"),
    "JVN": (":jigsaw:", "JVN 脆弱性データ"),
    "DEPSCAN": (":rotating_light:", "依存ライブラリ脆弱性"),
    "DEPSOPS": (":robot_face:", "Dependabot PR 自動運用"),
}

# Slack Incoming Webhook の text フィールド上限（40,000文字）に対する安全マージン
_MAX_SLACK_MESSAGE_LEN = 39000


def _sanitize_error(error: str) -> str:
    """エラーメッセージから接続文字列をマスクし、長さを制限する。"""
    sanitized = _CONN_STR_RE.sub("***masked-url***", error)
    if len(sanitized) > _MAX_ERROR_LEN:
        sanitized = sanitized[:_MAX_ERROR_LEN] + "..."
    return sanitized


def notify_success(
    crawler_type: CrawlerType,
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
        f">詳細: {DASHBOARD_URL}",
    ]
    _send_slack("\n".join(lines))


def notify_error(crawler_type: CrawlerType, error: str) -> None:
    """クローラーエラー時の Slack 通知（共通）。"""
    if not settings.SLACK_WEBHOOK_URL:
        return
    _, label = _CRAWLER_LABELS.get(crawler_type, (":bell:", crawler_type))
    _send_slack(f":warning: *{label}クローラーエラー*\n```{_sanitize_error(error)}```")


# ── 後方互換ラッパー（既存テスト・呼び出し元との互換性を維持） ──────


def notify_new_vulnerabilities(inserted: int, updated: int, deleted: int = 0) -> None:
    """KEV 成功通知（後方互換）。"""
    notify_success("KEV", inserted, updated, deleted)


def notify_osv_new_vulnerabilities(inserted: int, updated: int, deleted: int) -> None:
    """OSV 成功通知（後方互換）。"""
    notify_success("OSV", inserted, updated, deleted)


def notify_jvn_new_vulnerabilities(inserted: int, updated: int, deleted: int = 0) -> None:
    """JVN 成功通知（後方互換）。"""
    notify_success("JVN", inserted, updated, deleted)


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


def notify_depsops_crawl_error(error: str) -> None:
    """DEPSOPS エラー通知。"""
    notify_error("DEPSOPS", error)


# ── DEPSCAN 専用通知 ─────────────────────────────────────────────


def _truncate_for_slack(message: str) -> str:
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
    for repo in sorted(by_repo):
        lines.append(f"*{repo}*")
        lines.extend(format_package_lines(by_repo[repo]))
        lines.append("")

    message = _truncate_for_slack("\n".join(lines).rstrip())
    _send_slack(message)


# ── DEPSOPS 専用通知 ─────────────────────────────────────────────


def notify_dependabot_ops(
    merged: list[dict[str, Any]],
    flagged: list[dict[str, Any]],
) -> None:
    """DEPSOPS（Dependabot PR 自動運用）の実行結果を Slack に通知する。

    自動マージした PR・人の確認が必要な PR（メジャーバージョンアップ・CI 未設定・
    CI 失敗等）の両方を毎回通知する（監査性重視。0 件でも実行自体はしたことが
    分かるよう、merged/flagged が両方空の場合のみ送信をスキップする）。

    Args:
        merged: 自動マージした PR の辞書リスト
            （"repo_full_name"・"pr_number"・"title" を使用）
        flagged: 自動マージしなかった PR の辞書リスト
            （上記に加え "reason" を使用）
    """
    if not settings.SLACK_WEBHOOK_URL or (not merged and not flagged):
        return

    emoji, label = _CRAWLER_LABELS["DEPSOPS"]
    lines = [f"{emoji} *{label}*", ""]

    if merged:
        lines.append(f"✅ *自動マージ（{len(merged)}件）*")
        for item in merged:
            lines.append(f"• `{item['repo_full_name']}` #{item['pr_number']} {item['title']}")
        lines.append("")

    if flagged:
        lines.append(f"⚠️ *要確認（{len(flagged)}件）*")
        for item in flagged:
            lines.append(
                f"• `{item['repo_full_name']}` #{item['pr_number']} {item['title']}"
                f"（{item['reason']}）"
            )

    message = _truncate_for_slack("\n".join(lines).rstrip())
    _send_slack(message)


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
