"""MCP サーバー用のアクセストークン（JWT）の発行・検証モジュール。

ダッシュボードの GitHub ログイン済みユーザーが、自分専用の MCP トークンを発行し、
AI エージェントの MCP 設定に貼り付けて使う。トークンは発行したユーザーの GitHub
ユーザー名に紐づき、MCP サーバーは DEPSCAN / CODESCAN の結果を「そのユーザーが
所有するリポジトリのみ」に絞って返す（他の人に自分のリポジトリを見せないため）。

セッショントークン（`app.auth.session`、24 時間）とは `aud`（用途）クレームで区別する。
- MCP トークンはセッションとして使えない（PyJWT は `aud` 付きトークンを、audience を
  指定しない `decode` で拒否するため、`decode_session_token` が受け付けない）
- セッショントークンは MCP トークンとして使えない（`aud` が無いので `verify` が拒否する）
設定ファイルに貼って使う用途のため有効期限は 30 日と長い。署名鍵（SESSION_SECRET_KEY）の
ローテーションで全トークンを一括失効できる。
"""
import logging
from datetime import datetime, timedelta, timezone

import jwt

from app.core.config import settings

logger = logging.getLogger(__name__)

_ALGORITHM = "HS256"
_AUDIENCE = "cyberattack-info-mcp"
EXPIRES_DAYS = 30


def create_mcp_token(username: str) -> tuple[str, datetime]:
    """GitHub ユーザー名に紐づく MCP トークンと、その有効期限を発行する。"""
    expires_at = datetime.now(timezone.utc) + timedelta(days=EXPIRES_DAYS)
    payload = {"sub": username, "aud": _AUDIENCE, "exp": expires_at}
    return jwt.encode(payload, settings.SESSION_SECRET_KEY, algorithm=_ALGORITHM), expires_at


def verify_mcp_token(token: str) -> str | None:
    """MCP トークンを検証し、紐づく GitHub ユーザー名を返す。

    無効・期限切れ・用途(aud)違い・署名鍵未設定の場合は None を返す。
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
    username = payload.get("sub")
    return username if isinstance(username, str) and username else None
