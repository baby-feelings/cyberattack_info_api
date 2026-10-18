"""ダッシュボード用セッショントークン（JWT）の発行・検証モジュール。

GitHub OAuth ログイン成功後、ログインした GitHub ユーザー名を JWT に埋め込んで
フロントエンドへ返す。以降のリクエストではこのトークンを検証し、本人の
リポジトリのみに絞った DEPSCAN データへのアクセスを許可する。
"""
import logging
from datetime import UTC, datetime, timedelta

import jwt

from app.core.config import settings

logger = logging.getLogger(__name__)

_ALGORITHM = "HS256"
# 1回の有効期間。使う（更新する）たびにこの期間ぶん延長される（スライディング更新）。
# 数時間開かなかっただけでログインが切れないようにするため（Issue #337）
_EXPIRES_DAYS = 7
# ログイン（GitHub 認証）からの絶対上限。更新を繰り返してもこれを超えて延長しない
# （盗まれたトークンが使われ続けないよう、定期的に GitHub で再認証させる）
_MAX_SESSION_DAYS = 30


def create_session_token(username: str, login_at: datetime | None = None) -> str:
    """ログイン済み GitHub ユーザー名を埋め込んだセッショントークンを発行する。

    `login_at` は GitHub 認証した時刻。更新時は元の値を引き継ぎ、絶対上限の判定に使う。
    """
    now = datetime.now(UTC)
    payload = {
        "sub": username,
        "exp": now + timedelta(days=_EXPIRES_DAYS),
        "login_at": int((login_at or now).timestamp()),
    }
    return jwt.encode(payload, settings.SESSION_SECRET_KEY, algorithm=_ALGORITHM)


def _decode_payload(token: str) -> dict | None:
    """署名・期限を検証し、ペイロードを返す。無効・期限切れ・署名鍵未設定なら None。"""
    if not settings.SESSION_SECRET_KEY:
        return None
    try:
        return jwt.decode(token, settings.SESSION_SECRET_KEY, algorithms=[_ALGORITHM])
    except jwt.PyJWTError as exc:
        logger.info("Session token validation failed: %s", exc)
        return None


def decode_session_token(token: str) -> str | None:
    """セッショントークンを検証し、ログインユーザー名を返す。

    無効・期限切れ・署名鍵未設定の場合は None を返す（呼び出し側で401にする）。
    """
    payload = _decode_payload(token)
    username = payload.get("sub") if payload else None
    return username if isinstance(username, str) else None


def refresh_session_token(token: str) -> str | None:
    """有効なセッショントークンを、有効期間を延長した新しいトークンに交換する。

    期限切れ・無効、またはログインから `_MAX_SESSION_DAYS` を超えている場合は None
    （呼び出し側で401にし、GitHub で再ログインさせる）。
    `login_at` が無い旧形式のトークン（有効期間24時間だった頃に発行）は、今を起点にする。
    """
    payload = _decode_payload(token)
    username = payload.get("sub") if payload else None
    if payload is None or not isinstance(username, str):
        return None
    login_at_ts = payload.get("login_at")
    if isinstance(login_at_ts, int):
        login_at = datetime.fromtimestamp(login_at_ts, UTC)
    else:
        login_at = datetime.now(UTC)
    if datetime.now(UTC) - login_at > timedelta(days=_MAX_SESSION_DAYS):
        return None
    return create_session_token(username, login_at)
