"""期限が近づいた MCP トークンの Slack 通知（毎日1回の定期ジョブ）。

期限までの残りが `NOTICE_WINDOW`（3 日）以内の有効なトークンを、ユーザーごとにまとめて、
そのユーザー本人の Slack Webhook（設定画面で登録したもの）へ通知する。

- 通知は 1 トークンにつき 1 回（`expiry_notified_at` で管理）
- 失効済み・期限切れのトークンは対象外
- Webhook 未登録・通知オフのユーザーは送らず、「通知済み」にもしない（登録後に通知される）
- 送信に失敗したら「通知済み」にしない（翌日再試行される）
- 他のユーザーの Webhook には送らない。トークン本体は通知に載せない
"""
import logging
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.auth.account_store import get_webhook_for_user
from app.core.database import SessionLocal
from app.core.notifications import notify_mcp_token_expiry
from app.mcp_server.mcp_token_store import as_utc
from app.mcp_server.models import McpToken

logger = logging.getLogger(__name__)

# 期限のこの日数前から通知する
NOTICE_WINDOW = timedelta(days=3)


def find_expiring_tokens(db: Session, now: datetime | None = None) -> dict[str, list[McpToken]]:
    """期限が近い（残り NOTICE_WINDOW 以内）未通知の有効トークンを、ユーザーごとに返す。"""
    now = now or datetime.now(UTC)
    rows = (
        db.query(McpToken)
        .filter(
            McpToken.revoked_at.is_(None),
            McpToken.expiry_notified_at.is_(None),
            # OAuth の短命トークン（1時間）は自動更新される前提のため、通知の対象外
            McpToken.oauth_client_id.is_(None),
        )
        .all()
    )
    by_user: dict[str, list[McpToken]] = defaultdict(list)
    for row in rows:
        # SQLite は tz 情報を落とすため aware にそろえて比較する
        if now < as_utc(row.expires_at) <= now + NOTICE_WINDOW:
            by_user[row.username].append(row)
    return by_user


def send_expiry_notices(db: Session, now: datetime | None = None) -> int:
    """期限前通知を送り、送れたユーザーのトークンを「通知済み」にする。送ったユーザー数を返す。"""
    now = now or datetime.now(UTC)
    sent = 0
    for username, tokens in find_expiring_tokens(db, now).items():
        webhook = get_webhook_for_user(db, username)
        if webhook is None:
            logger.info("MCP token expiry notice skipped (no Slack webhook): user=%s", username)
            continue
        dates = [as_utc(t.expires_at).date().isoformat() for t in tokens]
        if not notify_mcp_token_expiry(webhook, dates):
            continue  # 失敗時は通知済みにしない（翌日再試行）
        for token in tokens:
            token.expiry_notified_at = now
        db.commit()
        sent += 1
    return sent


def run_mcp_token_expiry_notices(session_factory: Callable[[], Session] = SessionLocal) -> None:
    """定期ジョブの入口。失敗してもアプリを止めない（次回の実行で再試行される）。

    session_factory: DB セッションの取得元（テストでは差し替える）。
    """
    try:
        with session_factory() as db:
            sent = send_expiry_notices(db)
        logger.info("MCP token expiry notices sent to %d user(s)", sent)
    except Exception:  # noqa: BLE001 — 定期ジョブはどんな失敗でもスケジューラを止めない
        logger.exception("MCP token expiry notice job failed")
