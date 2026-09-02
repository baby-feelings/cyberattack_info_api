"""Slack 通知モジュール。
クローラーが脆弱性データを更新したとき、または失敗したとき Slack Webhook へ通知する。
SLACK_WEBHOOK_URL が未設定の場合は何もしない（サイレントスキップ）。
"""
import logging
import re
from typing import Any

import httpx

from app.core.config import settings
from app.core.types import CrawlerType

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

# 重大度の表示順（数値が小さいほど深刻。未知の値は最後に回す）
_SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

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
        f">詳細: {_DASHBOARD_URL}",
    ]
    _send_slack("\n".join(lines))


def notify_error(crawler_type: CrawlerType, error: str) -> None:
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


def _severity_rank(severity: str | None) -> int:
    """重大度文字列を表示順のランクに変換する（数値が小さいほど深刻）。"""
    return _SEVERITY_ORDER.get((severity or "UNKNOWN").upper(), len(_SEVERITY_ORDER))


def _format_package_lines(findings: list[dict[str, Any]]) -> list[str]:
    """1リポジトリ分の findings を (パッケージ名, インストール済みバージョン) 単位で
    1行に集約し、重大度が高い順に整形する。

    同一パッケージに複数の CVE がある場合、内訳を「CRITICAL×1, HIGH×2」のように
    件数でまとめ、修正済みバージョンは重複を除いて列挙する。
    """
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for finding in findings:
        key = (finding["package_name"], finding["installed_version"])
        groups.setdefault(key, []).append(finding)

    def group_sort_key(key: tuple[str, str]) -> tuple[int, str]:
        best_rank = min(_severity_rank(f.get("severity")) for f in groups[key])
        return (best_rank, key[0])

    lines = []
    for package_name, installed_version in sorted(groups, key=group_sort_key):
        group = groups[(package_name, installed_version)]

        sev_counts: dict[str, int] = {}
        for finding in group:
            sev = (finding.get("severity") or "UNKNOWN").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        sev_summary = ", ".join(
            f"{sev}×{count}"
            for sev, count in sorted(sev_counts.items(), key=lambda kv: _severity_rank(kv[0]))
        )

        fixed_versions = sorted({
            v for f in group for v in (f.get("fixed_versions") or [])
        })
        fix = ", ".join(fixed_versions) if fixed_versions else "未提供"

        lines.append(
            f"• {package_name} {installed_version} — {sev_summary}"
            f"（計{len(group)}件）→ 修正版: {fix}"
        )

    return lines


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
        lines.extend(_format_package_lines(by_repo[repo]))
        lines.append("")

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
