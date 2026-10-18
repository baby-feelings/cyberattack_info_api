"""MCP サーバー用の認証情報（MCP トークン・OAuth 接続）の管理 API ルーター。

POST   /auth/mcp-token                   – MCP トークンの発行（ログイン中ユーザー本人専用）
GET    /auth/mcp-tokens                  – 自分のトークンの一覧（トークン本体は含まない）
DELETE /auth/mcp-tokens/{token_id}       – トークンの個別失効
GET    /auth/oauth-connections           – OAuth で接続中のクライアントの一覧
DELETE /auth/oauth-connections/{client_id} – OAuth 接続の解除

いずれもセッションJWT（ダッシュボードのログイン）で本人確認し、他のユーザーのものは
一覧にも失効・解除にも現れない。
"""
import logging
from typing import Annotated, Literal

from fastapi import APIRouter, BackgroundTasks, Body, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth.account_store import get_webhook_for_user
from app.auth.dependencies import get_current_username
from app.core.database import get_db
from app.core.notifications.mcp_token import notify_mcp_token_issued
from app.mcp_server.mcp_token_store import (
    DEFAULT_DAYS,
    MAX_ACTIVE_TOKENS,
    TooManyTokensError,
    issue_token,
    list_tokens,
    revoke_token,
    token_status,
)
from app.mcp_server.models import McpToken
from app.mcp_server.oauth.connections import disconnect, list_connections

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


class IssueMcpTokenRequest(BaseModel):
    """MCP トークンの発行リクエスト。有効期限（日）は 7 / 30 / 90 から選ぶ。"""

    days: Literal[7, 30, 90] = DEFAULT_DAYS


def _mcp_token_out(row: McpToken) -> dict:
    """台帳の行を API 応答用に整形する（トークン本体は含まない）。"""
    return {
        "id": row.id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "expires_at": row.expires_at.isoformat(),
        "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
        "last_used_at": row.last_used_at.isoformat() if row.last_used_at else None,
        "status": token_status(row),
    }


@router.post(
    "/mcp-token",
    summary="MCPサーバー用アクセストークンを発行する（ログイン中ユーザー本人専用）",
)
def issue_mcp_token(
    db: Annotated[Session, Depends(get_db)],
    username: Annotated[str, Depends(get_current_username)],
    background_tasks: BackgroundTasks,
    body: Annotated[IssueMcpTokenRequest | None, Body()] = None,
) -> dict:
    """ログイン中ユーザー専用の MCP トークンを発行する（有効期限は 7/30/90 日、既定 30 日）。

    AI エージェントの MCP 設定に `Authorization: Bearer <token>` として貼り付けて使う。
    このトークンで参照できる DEPSCAN / CODESCAN は、発行したユーザー本人が所有する
    リポジトリのみ（他の人のリポジトリは見えない）。トークンは台帳に記録され、
    `GET /auth/mcp-tokens` で一覧、`DELETE /auth/mcp-tokens/{id}` で個別に失効できる。
    トークン本体は発行時の応答にだけ含まれ、再表示できない。有効なトークンは
    1ユーザー 10 個まで（超えると 409）。
    """
    days: int = body.days if body is not None else DEFAULT_DAYS
    try:
        token, row = issue_token(db, username, days)
    except TooManyTokensError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"有効なMCPトークンが上限（{MAX_ACTIVE_TOKENS}個）に達しています。"
            "使っていないトークンを失効してから発行してください。",
        ) from None
    logger.info("MCP token issued for %s (id=%s, days=%d)", username, row.id, days)
    # 本人の Slack（登録済みの場合のみ）へ事後通知する。送信は応答の後に行い、
    # 失敗しても発行は成功のまま
    webhook = get_webhook_for_user(db, username)
    if webhook is not None:
        background_tasks.add_task(
            notify_mcp_token_issued, webhook, row.expires_at.date().isoformat(),
        )
    return {"token": token, "username": username, **_mcp_token_out(row)}


@router.get("/mcp-tokens", summary="自分のMCPトークンの一覧（トークン本体は含まない）")
def list_mcp_tokens(
    db: Annotated[Session, Depends(get_db)],
    username: Annotated[str, Depends(get_current_username)],
) -> dict:
    """ログイン中ユーザー本人が発行したトークンを新しい順に返す（他のユーザーのものは含まない）。"""
    return {"tokens": [_mcp_token_out(row) for row in list_tokens(db, username)]}


@router.delete("/mcp-tokens/{token_id}", summary="自分のMCPトークンを失効する")
def revoke_mcp_token(
    token_id: str,
    db: Annotated[Session, Depends(get_db)],
    username: Annotated[str, Depends(get_current_username)],
) -> dict:
    """指定したトークンを失効する。以後そのトークンでの MCP 接続は 401 になる。

    他のユーザーのトークン、存在しないトークンはどちらも 404（他人のトークンの存在を
    推測させない）。失効済みのトークンに対しては何もせず成功を返す。
    """
    if not revoke_token(db, username, token_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found.")
    return {"id": token_id, "revoked": True}


@router.get(
    "/oauth-connections",
    summary="OAuth（MCP）で接続中のクライアントの一覧（自分が許可したもののみ）",
)
def list_oauth_connections(
    db: Annotated[Session, Depends(get_db)],
    username: Annotated[str, Depends(get_current_username)],
) -> dict:
    """ログイン中ユーザー本人が OAuth で許可したクライアント（Claude Code 等）を返す。

    クライアント名は登録時の自己申告（未確認）。他のユーザーのものは含まない。
    """
    return {"connections": list_connections(db, username)}


@router.delete(
    "/oauth-connections/{client_id}",
    summary="OAuth で接続中のクライアントを解除する（許可をすべて取り消す）",
)
def disconnect_oauth_client(
    client_id: str,
    db: Annotated[Session, Depends(get_db)],
    username: Annotated[str, Depends(get_current_username)],
) -> dict:
    """そのクライアントへの本人の許可（リフレッシュトークンと発行済みアクセストークン）を取り消す。

    以後そのクライアントは再認可が必要になる。他のユーザーの許可・存在しないクライアントは
    どちらも 404（他人の接続の存在を推測させない）。手動発行の MCP トークンには触れない。
    """
    if not disconnect(db, username, client_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connection not found.")
    logger.info("OAuth connection disconnected: user=%s client=%s", username, client_id)
    return {"client_id": client_id, "disconnected": True}
