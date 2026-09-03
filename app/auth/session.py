"""ダッシュボード用セッショントークン（JWT）の発行・検証モジュール。

GitHub OAuth ログイン成功後、ログインした GitHub ユーザー名を JWT に埋め込んで
フロントエンドへ返す。以降のリクエストではこのトークンを検証し、本人の
リポジトリのみに絞った DEPSCAN データへのアクセスを許可する。
"""
import logging
from datetime import datetime, timedelta, timezone

import jwt

from app.core.config import settings

logger = logging.getLogger(__name__)

_ALGORITHM = "HS256"
_EXPIRES_HOURS = 24


def create_session_token(username: str) -> str:
    """ログイン済み GitHub ユーザー名を埋め込んだセッショントークンを発行する。"""
    payload = {
        "sub": username,
        "exp": datetime.now(timezone.utc) + timedelta(hours=_EXPIRES_HOURS),
    }
    return jwt.encode(payload, settings.SESSION_SECRET_KEY, algorithm=_ALGORITHM)


def decode_session_token(token: str) -> str | None:
    """セッショントークンを検証し、ログインユーザー名を返す。

    無効・期限切れ・署名鍵未設定の場合は None を返す（呼び出し側で401にする）。
    """
    if not settings.SESSION_SECRET_KEY:
        return None
    try:
        payload = jwt.decode(token, settings.SESSION_SECRET_KEY, algorithms=[_ALGORITHM])
    except jwt.PyJWTError as exc:
        logger.info("Session token validation failed: %s", exc)
        return None
    username = payload.get("sub")
    return username if isinstance(username, str) else None
