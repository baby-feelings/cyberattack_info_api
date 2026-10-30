"""MCP トークンの台帳（`mcp_tokens` テーブル）の操作。

発行・一覧・個別失効・MCP 接続時の有効性確認を提供する。トークン本体（JWT）は保存せず、
`jti` に対応するトークンID・所有ユーザー・期限・失効・最終使用だけを持つ。
他のユーザーのトークンは、一覧にも失効にも現れない（所有ユーザーで必ず絞り込む）。
"""
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Final

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.core.db_utils import as_utc  # noqa: F401  既存の import 元（oauth 等）向けに再公開
from app.mcp_server.mcp_token import McpClaims, create_mcp_token
from app.mcp_server.models import McpToken

logger = logging.getLogger(__name__)

# 選べる有効期限（日）。個人利用の標準は 30 日。共有相手が増えるなら短くする
ALLOWED_DAYS: tuple[int, ...] = (7, 30, 90)
DEFAULT_DAYS: Final = 30

# 1ユーザーが同時に持てる有効なトークン数（無制限に増えるのを防ぐ）
MAX_ACTIVE_TOKENS = 10

# 最終使用日時を更新する最短間隔（MCP の呼び出しごとに書き込まないため）
_TOUCH_INTERVAL = timedelta(minutes=5)

# 失効・期限切れから、この日数を過ぎた行は発行時に掃除する
_RETENTION = timedelta(days=30)

# 一覧に出す最大件数
_LIST_LIMIT = 50


class TooManyTokensError(Exception):
    """有効なトークンの上限（MAX_ACTIVE_TOKENS）に達している。"""


def _now() -> datetime:
    return datetime.now(UTC)


def token_status(token: McpToken, now: datetime | None = None) -> str:
    """トークンの状態: revoked（失効）> expired（期限切れ）> active（有効）。"""
    if token.revoked_at is not None:
        return "revoked"
    if as_utc(token.expires_at) <= (now or _now()):
        return "expired"
    return "active"


def issue_token(db: Session, username: str, days: int = DEFAULT_DAYS) -> tuple[str, McpToken]:
    """トークンを発行し、台帳へ記録する。トークン本体（JWT）と台帳の行を返す。

    Raises:
        ValueError: days が ALLOWED_DAYS にない。
        TooManyTokensError: 有効なトークンが MAX_ACTIVE_TOKENS に達している。
    """
    if days not in ALLOWED_DAYS:
        raise ValueError(f"days must be one of {ALLOWED_DAYS}")
    now = _now()

    # 古い行（失効・期限切れから一定期間を過ぎたもの）を掃除してから数える
    _purge_stale(db, username, now)
    active = [t for t in _own_tokens(db, username) if token_status(t, now) == "active"]
    if len(active) >= MAX_ACTIVE_TOKENS:
        db.rollback()
        raise TooManyTokensError(MAX_ACTIVE_TOKENS)

    row = McpToken(id=str(uuid.uuid4()), username=username, expires_at=now + timedelta(days=days))
    db.add(row)
    db.commit()
    db.refresh(row)
    return create_mcp_token(username, row.id, as_utc(row.expires_at)), row


def _own_tokens(db: Session, username: str) -> list[McpToken]:
    """本人が手動で発行したトークン（OAuth 経由の短命トークンは含めない）。"""
    return (
        db.query(McpToken)
        .filter(McpToken.username == username, McpToken.oauth_client_id.is_(None))
        .all()
    )


def issue_oauth_token(
    db: Session, username: str, client_id: str, lifetime: timedelta,
) -> tuple[str, McpToken]:
    """OAuth 2.1 のトークン交換で、短命のアクセストークンを発行し台帳へ記録する。

    手動発行の上限（MAX_ACTIVE_TOKENS）の対象外。台帳に記録するため、個別の失効・
    `/mcp` での有効性確認は手動発行のトークンと同じ仕組みで効く。
    """
    now = _now()
    _purge_stale(db, username, now)
    row = McpToken(
        id=str(uuid.uuid4()), username=username, oauth_client_id=client_id,
        expires_at=now + lifetime,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return create_mcp_token(username, row.id, as_utc(row.expires_at)), row


def _purge_stale(db: Session, username: str, now: datetime) -> None:
    """失効・期限切れから一定期間（_RETENTION）を過ぎた本人の行を掃除する。"""
    cutoff = now - _RETENTION
    # synchronize_session=False: SQLite は tz 情報を落とすため、Python 側での比較評価を避ける
    db.execute(
        delete(McpToken).where(
            McpToken.username == username,
            ((McpToken.revoked_at.is_not(None)) & (McpToken.revoked_at < cutoff))
            | (McpToken.expires_at < cutoff),
        ).execution_options(synchronize_session=False),
    )


def list_tokens(db: Session, username: str) -> list[McpToken]:
    """本人のトークンを、新しい順に返す（他のユーザーのものは含まない）。"""
    return (
        db.query(McpToken)
        .filter(McpToken.username == username, McpToken.oauth_client_id.is_(None))
        .order_by(McpToken.created_at.desc())
        .limit(_LIST_LIMIT)
        .all()
    )


def revoke_token(db: Session, username: str, token_id: str) -> bool:
    """本人のトークンを失効する。対象が無い（他人のものを含む）なら False。失効済みでも True。"""
    row = db.query(McpToken).filter(
        McpToken.id == token_id, McpToken.username == username,
    ).first()
    if row is None:
        return False
    if row.revoked_at is None:
        row.revoked_at = _now()
        db.commit()
        logger.info("MCP token revoked: user=%s id=%s", username, token_id)
    return True


def is_usable(db: Session, claims: McpClaims) -> bool:
    """MCP 接続時の確認: 台帳に存在し、トークン発行者本人のもので、失効していない。

    通れば最終使用日時を更新する（`_TOUCH_INTERVAL` で間引く）。署名・期限は
    `verify_mcp_token` が検証済みの前提。
    """
    row = db.get(McpToken, claims.token_id)
    if row is None or row.username != claims.username or row.revoked_at is not None:
        return False
    now = _now()
    if row.last_used_at is None or now - as_utc(row.last_used_at) >= _TOUCH_INTERVAL:
        row.last_used_at = now
        db.commit()
    return True


def revoke_oauth_tokens(db: Session, username: str, client_id: str) -> int:
    """本人がそのクライアントに発行した OAuth のアクセストークンを、すべて失効する（件数を返す）。

    接続解除（ダッシュボード）・`/revoke` で使う。手動発行のトークン
    （oauth_client_id が null）には触れない。
    """
    now = _now()
    rows = (
        db.query(McpToken)
        .filter(
            McpToken.username == username,
            McpToken.oauth_client_id == client_id,
            McpToken.revoked_at.is_(None),
        )
        .all()
    )
    for row in rows:
        row.revoked_at = now
    db.commit()
    return len(rows)
