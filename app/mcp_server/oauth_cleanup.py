"""使われない OAuth 接続・登録の自動整理（毎日1回の定期ジョブ）。

MCP クライアント（Claude Code 等）は `/mcp` で認証するたびにクライアントを自動登録するため、
認証のやり直しや失敗で「許可はしたが一度も使われていない接続」が残りやすい。
放置すると、使われないリフレッシュトークンが有効なまま残り、設定画面の一覧も読みにくくなる。

- 接続から `UNUSED_CONNECTION_TTL`（7 日）を過ぎても一度も使われていない接続は、解除する
  （許可の取り消しは、設定画面の「接続解除」と同じ。再度使うときは認可し直せばよい）
- 一度でも使われた接続には触れない（使われなくなっても、許可の期限（30 日）で自然に切れる）
- 一度もトークン交換に使われず `UNUSED_RETENTION` を過ぎたクライアント登録は、削除する
"""
import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.auth.models import OAuthRefreshToken
from app.core.database import SessionLocal
from app.mcp_server import oauth_clients, oauth_connections

logger = logging.getLogger(__name__)

# 接続してから、この期間使われなければ解除する
UNUSED_CONNECTION_TTL = timedelta(days=7)


def disconnect_unused_connections(db: Session, now: datetime | None = None) -> int:
    """一度も使われないまま `UNUSED_CONNECTION_TTL` を過ぎた接続を解除し、その件数を返す。"""
    now = now or datetime.now(UTC)
    cutoff = now - UNUSED_CONNECTION_TTL
    usernames = [
        row[0]
        for row in db.query(OAuthRefreshToken.username)
        .filter(OAuthRefreshToken.revoked_at.is_(None))
        .distinct()
        .all()
    ]
    disconnected = 0
    for username in usernames:
        for conn in oauth_connections.list_connections(db, username, now):
            connected_at = conn["connected_at"]
            if conn["last_used_at"] is not None or connected_at is None:
                continue  # 一度でも使われた接続には触れない
            if datetime.fromisoformat(connected_at) < cutoff:
                if oauth_connections.disconnect(db, username, conn["client_id"]):
                    disconnected += 1
    return disconnected


def run_oauth_cleanup(session_factory: Callable[[], Session] = SessionLocal) -> None:
    """定期ジョブの入口。失敗してもアプリを止めない（次回の実行で再試行される）。

    session_factory: DB セッションの取得元（テストでは差し替える）。
    """
    try:
        with session_factory() as db:
            disconnected = disconnect_unused_connections(db)
            purged = oauth_clients.purge_unused_clients(db)
        logger.info(
            "OAuth cleanup: %d unused connection(s) disconnected, %d unused client(s) purged",
            disconnected, purged,
        )
    except Exception:  # noqa: BLE001 — 定期ジョブはどんな失敗でもスケジューラを止めない
        logger.exception("OAuth cleanup job failed")
