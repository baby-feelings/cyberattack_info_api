"""クローラー（KEV/OSV/JVN/CODESCAN）の成功・エラー通知。"""
import re

from app.core.notifications import recipients as recipient_resolver
from app.core.notifications.base import CRAWLER_LABELS, Notifier
from app.core.notifications.slack import DASHBOARD_URL
from app.core.types import CrawlerType

# 接続文字列パターン（postgresql:// / sqlite:// 等）をマスク
_CONN_STR_RE = re.compile(r"\b\w+://[^\s]+")
_MAX_ERROR_LEN = 200


def sanitize_error(error: str) -> str:
    """エラーメッセージから接続文字列をマスクし、長さを制限する。"""
    sanitized = _CONN_STR_RE.sub("***masked-url***", error)
    if len(sanitized) > _MAX_ERROR_LEN:
        sanitized = sanitized[:_MAX_ERROR_LEN] + "..."
    return sanitized


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
        return recipient_resolver.resolve_recipients(self._crawler_type)

    def build_message(self) -> str:
        emoji, label = CRAWLER_LABELS.get(self._crawler_type, (":bell:", self._crawler_type))
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
        return recipient_resolver.resolve_admin_recipient()

    def build_message(self) -> str:
        _, label = CRAWLER_LABELS.get(self._crawler_type, (":bell:", self._crawler_type))
        return f":warning: *{label}クローラーエラー*\n```{sanitize_error(self._error)}```"


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
