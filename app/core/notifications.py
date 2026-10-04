"""Slack 通知モジュール。
クローラーが脆弱性データを更新したとき、または失敗したとき Slack Webhook へ通知する。

Issue #227 より前は固定の `SLACK_WEBHOOK_URL` 環境変数1本のみへ送信していたが、
ダッシュボードから各ユーザーが自分の Slack Webhook を登録できるようになったのに
伴い、検知結果の通知先は `app.auth.account_store`（`UserAccount` テーブル）から
動的に解決する方式へ移行した。KEV/OSV/JVN は特定リポジトリに紐づかないグローバルな
脅威情報のため、通知を有効にしている**全登録ユーザー**へブロードキャストする。
DEPSCAN/DEPSOPS/CODESCAN の毎日クロール（`GITHUB_USERNAME` 自身のリポジトリ対象）
は、`GITHUB_USERNAME` 自身が登録した Webhook にのみ送る（無関係な他ユーザーに
baby-feelings 自身のリポジトリの通知が届いてしまわないようにするため）。

**エラー通知（`notify_error`）だけは例外**で、crawler_type に関わらず常に
管理者（`GITHUB_USERNAME`）自身が登録した Webhook にのみ送る（全登録ユーザーへの
ブロードキャストは行わない）。クローラーの内部エラーは運用担当者が対応すべき情報で
あり、無関係なユーザーに通知してもノイズにしかならないため。
"""
import logging
import re
from abc import ABC, abstractmethod
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.finding_format import format_package_lines
from app.core.types import CrawlerType

logger = logging.getLogger(__name__)

_WEBHOOK_TIMEOUT = 10.0
DASHBOARD_URL = "https://cyberattackinfoapi.vercel.app/"

# グローバル（リポジトリに紐づかない）扱いにするクローラー種別。
# それ以外（DEPSCAN/DEPSOPS/CODESCAN）は GITHUB_USERNAME 自身の通知先にのみ送る
_GLOBAL_CRAWLER_TYPES: frozenset[str] = frozenset({"KEV", "OSV", "JVN"})

# Slack Incoming Webhook の正規のURLプレフィックス（登録時のバリデーション用）
SLACK_WEBHOOK_URL_PREFIX = "https://hooks.slack.com/"

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
    "CODESCAN": (":mag:", "自アプリコード脆弱性"),
}

# Slack Incoming Webhook の text フィールド上限（40,000文字）に対する安全マージン
_MAX_SLACK_MESSAGE_LEN = 39000


def _sanitize_error(error: str) -> str:
    """エラーメッセージから接続文字列をマスクし、長さを制限する。"""
    sanitized = _CONN_STR_RE.sub("***masked-url***", error)
    if len(sanitized) > _MAX_ERROR_LEN:
        sanitized = sanitized[:_MAX_ERROR_LEN] + "..."
    return sanitized


def _resolve_recipients(crawler_type: CrawlerType) -> list[str]:
    """クローラー種別から、Slack通知の送信先URL一覧を解決する。

    KEV/OSV/JVN はグローバルな脅威情報のため通知が有効な全登録ユーザーへ、
    DEPSCAN/DEPSOPS/CODESCAN（baby-feelings＝GITHUB_USERNAME自身の毎日クロール）
    は GITHUB_USERNAME 自身が登録したWebhookにのみ送る。
    """
    from app.auth.account_store import list_all_webhooks

    db: Session = SessionLocal()
    try:
        if crawler_type in _GLOBAL_CRAWLER_TYPES:
            return list_all_webhooks(db)
        return _resolve_admin_recipient(db)
    finally:
        db.close()


def _resolve_admin_recipient(db: Session | None = None) -> list[str]:
    """管理者（GITHUB_USERNAME）自身が登録したWebhookのみを返す。

    エラー通知は、検知結果の通知（notify_success等）とは異なりKEV/OSV/JVNの
    ようなグローバル種別でも全登録ユーザーへブロードキャストせず、常に運用担当
    である管理者のSlackにのみ送る（クローラーの内部エラーは各ユーザーが対応
    できる情報ではなく、無関係なユーザーに通知するとノイズ・情報漏洩になるため）。
    """
    from app.auth.account_store import get_webhook_for_user

    owns_session = db is None
    db = db if db is not None else SessionLocal()
    try:
        webhook = get_webhook_for_user(db, settings.GITHUB_USERNAME)
        return [webhook] if webhook else []
    finally:
        if owns_session:
            db.close()


class Notifier(ABC):
    """Slack 通知の共通フロー（Template Method）。

    「送るべき内容があるか判定 → 送信先を解決 → メッセージを組み立て → 全送信先へ送る」という
    流れを `send` に集約し、サブクラスは次の3点だけを差し替える。

    - `has_content`: 通知すべき内容があるか（変化なし・0件のときは送らない）
    - `default_recipients`: `recipients` 省略時の送信先（既定経路）
    - `build_message`: Slack に送る本文
    """

    def __init__(self, recipients: list[str] | None = None) -> None:
        # 送信先を明示指定する場合（登録済み他ユーザーの個別クロール結果を本人にだけ送る等）
        self._recipients = recipients

    @abstractmethod
    def has_content(self) -> bool:
        """通知すべき内容があるか。False なら送信先の解決もせずに終了する。"""

    @abstractmethod
    def default_recipients(self) -> list[str]:
        """`recipients` 未指定時の送信先URL一覧（毎日クロールが呼ぶ既定の経路）。"""

    @abstractmethod
    def build_message(self) -> str:
        """Slack に送る本文を組み立てる。"""

    def send(self) -> None:
        if not self.has_content():
            return
        targets = self.default_recipients() if self._recipients is None else self._recipients
        if not targets:
            return
        message = self.build_message()
        for url in targets:
            _send_slack(message, url)


class CrawlerSuccessNotifier(Notifier):
    """クローラー成功時の通知（KEV/OSV/JVN/CODESCAN 共通。変化がなければ通知しない）。"""

    def __init__(
        self, crawler_type: CrawlerType, inserted: int, updated: int, deleted: int = 0,
        recipients: list[str] | None = None,
    ) -> None:
        super().__init__(recipients)
        self._crawler_type = crawler_type
        self._inserted = inserted
        self._updated = updated
        self._deleted = deleted

    def has_content(self) -> bool:
        return not (self._inserted == 0 and self._updated == 0 and self._deleted == 0)

    def default_recipients(self) -> list[str]:
        return _resolve_recipients(self._crawler_type)

    def build_message(self) -> str:
        emoji, label = _CRAWLER_LABELS.get(self._crawler_type, (":bell:", self._crawler_type))
        lines = [
            f"{emoji} *{label}更新通知*",
            f">新規追加: *{self._inserted} 件*　更新: {self._updated} 件"
            + (f"　削除: {self._deleted} 件" if self._deleted else ""),
            f">詳細: {DASHBOARD_URL}",
        ]
        return "\n".join(lines)


class CrawlerErrorNotifier(Notifier):
    """クローラーエラー時の通知。

    検知結果の通知とは異なり、crawler_type に関わらず常に管理者（GITHUB_USERNAME）自身が
    登録した Webhook にのみ送る（KEV/OSV/JVN のエラーでも全登録ユーザーへは送らない）。
    """

    def __init__(
        self, crawler_type: CrawlerType, error: str, recipients: list[str] | None = None,
    ) -> None:
        super().__init__(recipients)
        self._crawler_type = crawler_type
        self._error = error

    def has_content(self) -> bool:
        return True

    def default_recipients(self) -> list[str]:
        return _resolve_admin_recipient()

    def build_message(self) -> str:
        _, label = _CRAWLER_LABELS.get(self._crawler_type, (":bell:", self._crawler_type))
        return f":warning: *{label}クローラーエラー*\n```{_sanitize_error(self._error)}```"


def notify_success(
    crawler_type: CrawlerType,
    inserted: int,
    updated: int,
    deleted: int = 0,
    *,
    recipients: list[str] | None = None,
) -> None:
    """クローラー成功時の Slack 通知（共通）。変化がなければ通知しない。

    Args:
        recipients: 送信先を明示的に指定する場合（登録済み他ユーザーの
            個別クロール結果を、その本人にだけ送る場合等）に使う。省略時は
            `crawler_type` から自動解決する（毎日クロールが呼ぶ既定の経路）。
    """
    CrawlerSuccessNotifier(crawler_type, inserted, updated, deleted, recipients).send()


def notify_error(
    crawler_type: CrawlerType, error: str, *, recipients: list[str] | None = None,
) -> None:
    """クローラーエラー時の Slack 通知（共通）。常に管理者の Webhook にのみ送る。"""
    CrawlerErrorNotifier(crawler_type, error, recipients).send()


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


class DependencyFindingsNotifier(Notifier):
    """依存ライブラリ脆弱性の新規検知を、リポジトリ別にグルーピングした1通のダイジェストで通知する。

    findings は DependencyFinding 相当のフィールドを持つ辞書のリスト
    （"repo_full_name"・"package_name"・"installed_version"・"severity"・"fixed_versions"・
    "osv_id" を使用。ORM セッションクローズ後の DetachedInstanceError を避けるため、
    ORM オブジェクトではなく辞書で受け取る）。
    """

    def __init__(
        self, new_findings: list[dict[str, Any]], recipients: list[str] | None = None,
    ) -> None:
        super().__init__(recipients)
        self._findings = new_findings

    def has_content(self) -> bool:
        return bool(self._findings)

    def default_recipients(self) -> list[str]:
        # 省略時は GITHUB_USERNAME 自身の登録済み Webhook へ送る（毎日クロールの既定経路）
        return _resolve_recipients("DEPSCAN")

    def build_message(self) -> str:
        emoji, label = _CRAWLER_LABELS["DEPSCAN"]
        by_repo: dict[str, list[dict[str, Any]]] = {}
        for finding in self._findings:
            by_repo.setdefault(finding["repo_full_name"], []).append(finding)

        lines = [f"{emoji} *{label}を{len(self._findings)}件検知*", ""]
        for repo in sorted(by_repo):
            lines.append(f"*{repo}*")
            lines.extend(format_package_lines(by_repo[repo]))
            lines.append("")
        return _truncate_for_slack("\n".join(lines).rstrip())


def notify_dependency_findings(
    new_findings: list[dict[str, Any]], *, recipients: list[str] | None = None,
) -> None:
    """依存ライブラリ脆弱性の新規検知を Slack に1通のダイジェストとして通知する。
    リポジトリ別にグルーピングし、findings が空なら何もしない。

    Args:
        new_findings: DependencyFinding 相当のフィールドを持つ辞書のリスト
        recipients: 送信先を明示的に指定する場合に使う。省略時は
            GITHUB_USERNAME 自身の登録済みWebhookへ送る（毎日クロールの既定経路）。
    """
    DependencyFindingsNotifier(new_findings, recipients).send()


# ── DEPSOPS 専用通知 ─────────────────────────────────────────────


class DependabotOpsNotifier(Notifier):
    """DEPSOPS の実行結果（自動マージ・要確認）の通知。

    自動マージした PR・人の確認が必要な PR の両方を毎回通知する（監査性重視。
    merged/flagged が両方空の場合のみ送信をスキップする）。
    """

    def __init__(
        self,
        merged: list[dict[str, Any]],
        flagged: list[dict[str, Any]],
        recipients: list[str] | None = None,
    ) -> None:
        super().__init__(recipients)
        self._merged = merged
        self._flagged = flagged

    def has_content(self) -> bool:
        return bool(self._merged or self._flagged)

    def default_recipients(self) -> list[str]:
        return _resolve_recipients("DEPSOPS")

    def build_message(self) -> str:
        emoji, label = _CRAWLER_LABELS["DEPSOPS"]
        lines = [f"{emoji} *{label}*", ""]

        if self._merged:
            lines.append(f"✅ *自動マージ（{len(self._merged)}件）*")
            for item in self._merged:
                lines.append(f"• `{item['repo_full_name']}` #{item['pr_number']} {item['title']}")
            lines.append("")

        if self._flagged:
            lines.append(f"⚠️ *要確認（{len(self._flagged)}件）*")
            for item in self._flagged:
                lines.append(
                    f"• `{item['repo_full_name']}` #{item['pr_number']} {item['title']}"
                    f"（{item['reason']}）"
                )
        return _truncate_for_slack("\n".join(lines).rstrip())


def notify_dependabot_ops(
    merged: list[dict[str, Any]],
    flagged: list[dict[str, Any]],
    *,
    recipients: list[str] | None = None,
) -> None:
    """DEPSOPS（Dependabot PR 自動運用）の実行結果を Slack に通知する。

    Args:
        merged: 自動マージした PR の辞書リスト（"repo_full_name"・"pr_number"・"title"）
        flagged: 自動マージしなかった PR の辞書リスト（上記に加え "reason"）
        recipients: 送信先を明示的に指定する場合に使う。省略時は
            GITHUB_USERNAME 自身の登録済みWebhookへ送る。
    """
    DependabotOpsNotifier(merged, flagged, recipients).send()


# ── ユーザー別Webhook登録（Issue #227） ──────────────────────────


def is_valid_slack_webhook_url(url: str) -> bool:
    """登録画面での簡易フォーマットチェック（本物のSlack Webhookかどうかは
    `send_test_notification` の実際の送信結果で確認する）。
    """
    return url.startswith(SLACK_WEBHOOK_URL_PREFIX)


def send_test_notification(webhook_url: str, username: str) -> bool:
    """Webhook登録時のテスト送信。送信に成功したかどうかを返す
    （設定画面はこの結果を見てから登録を確定するかどうかを判断する）。
    """
    message = (
        ":white_check_mark: *通知テスト*\n"
        f">{username} さんのアカウントでSlack通知が有効になりました。\n"
        f">詳細: {DASHBOARD_URL}"
    )
    return _send_slack(message, webhook_url)


# ── Slack 送信 ────────────────────────────────────────────────────


def _send_slack(message: str, webhook_url: str) -> bool:
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
