"""OAuth で接続中のクライアントの一覧と、接続解除（Issue #303）。

ダッシュボードの設定画面が使う。本人（ログイン中のユーザー）が許可したクライアントだけを扱い、
他のユーザーのものは一覧にも解除にも現れない。

- 「接続中」= 有効（失効・期限切れでない）なリフレッシュトークンの先頭（未使用）を持つクライアント
- 接続解除 = そのクライアントへの本人の許可をすべて取り消す（全系統のリフレッシュトークンと、
  発行済みの OAuth アクセストークン。`/revoke` でリフレッシュトークンを失効したのと同じ）
"""
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.mcp_server.mcp_token_store import as_utc, revoke_oauth_tokens
from app.mcp_server.models import McpToken, OAuthClient, OAuthRefreshToken
from app.mcp_server.oauth import refresh as oauth_refresh

# クライアント名が無い（自己申告されなかった）ときの表示
_NO_NAME = "（名前なし）"
# 画面に出すクライアント名の最大長（自己申告のため切り詰める）
_MAX_NAME_CHARS = 80


def _client_name(db: Session, client_id: str) -> str:
    """登録時に自己申告されたクライアント名（未確認）。無ければ _NO_NAME。"""
    row = db.get(OAuthClient, client_id)
    if row is None:
        return _NO_NAME
    try:
        name = json.loads(row.client_info_json).get("client_name")
    except ValueError:
        name = None
    return str(name)[:_MAX_NAME_CHARS] if name else _NO_NAME


def _iso(dt: datetime | None) -> str | None:
    return as_utc(dt).isoformat() if dt else None


def list_connections(
    db: Session, username: str, now: datetime | None = None,
) -> list[dict[str, Any]]:
    """本人が OAuth で接続中のクライアントを、最近更新された順に返す。"""
    now = now or datetime.now(UTC)
    heads = (
        db.query(OAuthRefreshToken)
        .filter(
            OAuthRefreshToken.username == username,
            OAuthRefreshToken.revoked_at.is_(None),
            OAuthRefreshToken.used_at.is_(None),
        )
        .all()
    )
    # SQLite は tz 情報を落とすため、期限は Python 側で aware にそろえて比較する
    active = [r for r in heads if as_utc(r.expires_at) > now]

    connections: list[dict[str, Any]] = []
    for head in active:
        first_connected = db.query(func.min(OAuthRefreshToken.created_at)).filter(
            OAuthRefreshToken.username == username,
            OAuthRefreshToken.client_id == head.client_id,
        ).scalar()
        last_used = db.query(func.max(McpToken.last_used_at)).filter(
            McpToken.username == username, McpToken.oauth_client_id == head.client_id,
        ).scalar()
        connections.append({
            "client_id": head.client_id,
            "client_name": _client_name(db, head.client_id),
            "connected_at": _iso(first_connected),
            "last_refreshed_at": _iso(head.created_at),
            "last_used_at": _iso(last_used),
            "expires_at": _iso(head.expires_at),
        })
    connections.sort(key=lambda c: c["last_refreshed_at"] or "", reverse=True)
    return connections


def disconnect(db: Session, username: str, client_id: str) -> bool:
    """本人のそのクライアントへの許可をすべて取り消す。取り消すものが無ければ False。

    他のユーザーの許可には触れない。手動発行のトークン（oauth_client_id が null）にも触れない。
    """
    had_grants = (
        db.query(OAuthRefreshToken)
        .filter(
            OAuthRefreshToken.username == username,
            OAuthRefreshToken.client_id == client_id,
            OAuthRefreshToken.revoked_at.is_(None),
        )
        .count()
    ) > 0
    oauth_refresh.revoke_client_grants(db, username, client_id)
    revoked_access = revoke_oauth_tokens(db, username, client_id)
    return had_grants or revoked_access > 0
