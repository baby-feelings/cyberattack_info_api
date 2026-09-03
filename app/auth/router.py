"""GitHub ログイン（DEPSCAN ダッシュボードのアクセス制御）API ルーター。

GET /auth/github/login     – GitHub の認可画面へリダイレクト
GET /auth/github/callback  – 認可コードを受け取り、セッショントークンを発行して
                              フロントエンドへリダイレクト（オンデマンドスキャンも開始）
GET /auth/scan-status      – ログイン中ユーザーのオンデマンドスキャン進捗を返す
"""
import logging
import secrets
import threading
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from fastapi.security import APIKeyHeader
from sqlalchemy.orm import Session

from app.auth.github_oauth import (
    build_authorize_url,
    exchange_code_for_token,
    get_authenticated_user_login,
)
from app.auth.session import create_session_token, decode_session_token
from app.core.config import settings
from app.core.database import get_db
from app.depscan.crawler import get_user_scan_status, run_depscan_for_user, should_rescan_for_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

_CALLBACK_PATH = "/auth/github/callback"
_STATE_COOKIE = "gh_oauth_state"

_bearer_header = APIKeyHeader(name="Authorization", auto_error=False)


def get_current_username(authorization: str | None = Depends(_bearer_header)) -> str:
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


@router.get(
    "/github/login",
    summary="GitHub 認可画面へリダイレクト（DEPSCAN ダッシュボードログイン用）",
)
def github_login() -> RedirectResponse:
    if not settings.GITHUB_OAUTH_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="GitHub OAuth is not configured (GITHUB_OAUTH_CLIENT_ID is not set).",
        )
    state = secrets.token_urlsafe(24)
    redirect_uri = f"{settings.API_BASE_URL_FOR_OAUTH}{_CALLBACK_PATH}"
    authorize_url = build_authorize_url(settings.GITHUB_OAUTH_CLIENT_ID, redirect_uri, state)
    resp = RedirectResponse(url=authorize_url, status_code=status.HTTP_302_FOUND)
    # CSRF対策: state をバックエンド自身のドメインに紐づく短命Cookieとして保持し、
    # コールバック時に GitHub から返ってきた state と一致するか検証する
    resp.set_cookie(
        _STATE_COOKIE, state, max_age=600, httponly=True, secure=True, samesite="lax",
    )
    return resp


@router.get("/github/callback", summary="GitHub OAuth コールバック（内部利用）")
def github_callback(
    db: Annotated[Session, Depends(get_db)],
    code: str = Query(...),
    state: str = Query(...),
    gh_oauth_state: str | None = Cookie(None),
) -> RedirectResponse:
    if not settings.GITHUB_OAUTH_CLIENT_ID or not settings.GITHUB_OAUTH_CLIENT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="GitHub OAuth is not configured.",
        )
    if not gh_oauth_state or not secrets.compare_digest(gh_oauth_state, state):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OAuth state.")

    redirect_uri = f"{settings.API_BASE_URL_FOR_OAUTH}{_CALLBACK_PATH}"
    access_token = exchange_code_for_token(
        settings.GITHUB_OAUTH_CLIENT_ID, settings.GITHUB_OAUTH_CLIENT_SECRET, code, redirect_uri,
    )
    username = get_authenticated_user_login(access_token)
    logger.info("DEPSCAN dashboard login: %s", username)

    # 直近 RESCAN_INTERVAL_HOURS 時間以内にスキャン済みなら再スキャンせず DB の結果を
    # そのまま使う（毎回ログインの度にスキャンして待たせないようにするため）。
    # スキャンする場合はバックグラウンドスレッドで実行し、ここでは待たずセッション発行へ進む
    if should_rescan_for_user(db, username):
        thread = threading.Thread(
            target=run_depscan_for_user, args=(username, access_token),
            name=f"depscan-user-{username}", daemon=True,
        )
        thread.start()
    else:
        logger.info("DEPSCAN on-demand scan skipped for %s (recently scanned)", username)

    session_token = create_session_token(username)
    redirect_url = (
        f"{settings.FRONTEND_URL.rstrip('/')}/?depscan_token={session_token}&depscan_user={username}"
    )
    resp = RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)
    resp.delete_cookie(_STATE_COOKIE)
    return resp


@router.get("/scan-status", summary="ログイン中ユーザーのオンデマンドスキャン進捗を取得")
def scan_status(
    db: Annotated[Session, Depends(get_db)],
    username: Annotated[str, Depends(get_current_username)],
) -> dict:
    scan = get_user_scan_status(db, username)
    if scan is None:
        return {"username": username, "status": "not_started"}
    return {
        "username": username,
        "status": scan.status,
        "repos_scanned": scan.repos_scanned,
        "started_at": scan.started_at.isoformat(),
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "error_message": scan.error_message,
    }
