"""MCP サーバー用アクセストークン（JWT）の発行・検証モジュール。

ダッシュボードの GitHub ログイン済みユーザーが、自分専用の MCP トークンを発行し、
AI エージェントの MCP 設定に貼り付けて使う。トークンは発行したユーザーの GitHub
ユーザー名に紐づき、MCP サーバーは DEPSCAN / CODESCAN の結果を「そのユーザーが
所有するリポジトリのみ」に絞って返す（他の人に自分のリポジトリを見せないため）。

セッショントークン（`app.auth.session`、24 時間）とは `aud`（用途）クレームで区別する。
- MCP トークンはセッションとして使えない（PyJWT は `aud` 付きトークンを、audience を
  指定しない `decode` で拒否するため、`decode_session_token` が受け付けない）
- セッショントークンは MCP トークンとして使えない（`aud` が無いので `verify` が拒否する）

JWT は `jti`（トークンID）を持ち、発行時に台帳（`app.auth.models.McpToken`）へ記録する。
個別の失効・一覧・最終使用日時は台帳側で管理する（`app.auth.mcp_token_store`）。この
モジュールは署名・期限・用途・必須クレームの検証だけを担い、失効の確認は呼び出し側が行う。
"""
import logging
from dataclasses import dataclass
from datetime import datetime

import jwt

from app.core.config import settings

logger = logging.getLogger(__name__)

_ALGORITHM = "HS256"
_AUDIENCE = "cyberattack-info-mcp"


@dataclass(frozen=True)
class McpClaims:
    """検証済み MCP トークンのクレーム。"""

    username: str
    token_id: str


def create_mcp_token(username: str, token_id: str, expires_at: datetime) -> str:
    """GitHub ユーザー名とトークンIDを埋め込んだ MCP トークン（JWT）を署名して返す。"""
    payload = {"sub": username, "jti": token_id, "aud": _AUDIENCE, "exp": expires_at}
    return jwt.encode(payload, settings.SESSION_SECRET_KEY, algorithm=_ALGORITHM)


def verify_mcp_token(token: str) -> McpClaims | None:
    """MCP トークンの署名・期限・用途(aud)・必須クレーム（sub, jti）を検証する。

    無効・期限切れ・用途違い・署名鍵未設定・jti が無い旧形式のトークンは None を返す
    （jti が無いトークンは台帳に無く、個別に失効できないため受け付けない）。
    """
    if not settings.SESSION_SECRET_KEY:
        return None
    try:
        payload = jwt.decode(
            token, settings.SESSION_SECRET_KEY, algorithms=[_ALGORITHM], audience=_AUDIENCE,
        )
    except jwt.PyJWTError as exc:
        logger.info("MCP token validation failed: %s", exc)
        return None
    username, token_id = payload.get("sub"), payload.get("jti")
    if not (isinstance(username, str) and username and isinstance(token_id, str) and token_id):
        return None
    return McpClaims(username=username, token_id=token_id)
