"""ログイン中ユーザーの認証（`Authorization: Bearer <セッションJWT>`）を行う依存関数。

DEPSCAN・CODESCAN・DEPSOPS など、他ドメインのルーターが X-API-KEY 認証の代わりに使う。
"""
from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader

from app.auth.session import decode_session_token

bearer_header = APIKeyHeader(name="Authorization", auto_error=False)


def get_current_username(authorization: str | None = Depends(bearer_header)) -> str:
    """`Authorization: Bearer <token>` を検証し、ログイン中の GitHub ユーザー名を返す。

    DEPSCAN の他エンドポイント（`app.depscan.router`）から、X-API-KEY 認証の
    代わりに使う依存関数。
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header. Expected 'Bearer <token>'.",
        )
    token = authorization[len("bearer "):].strip()
    username = decode_session_token(token)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session token.",
        )
    return username
