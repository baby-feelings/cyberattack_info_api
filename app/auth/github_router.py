"""GitHub ログイン（DEPSCAN ダッシュボードのアクセス制御）API ルーター。

GET  /auth/github/login     – GitHub の認可画面へリダイレクト
GET  /auth/github/callback  – 認可コードを受け取り、短命・使い捨ての交換コードを
                               発行してフロントエンドへリダイレクト
                               （オンデマンドスキャンも開始。RFC 9700対応のため
                               セッションJWT自体はURLクエリに載せない）
POST /auth/exchange         – 交換コードをセッションJWTに交換する（使い捨て）

セッションJWTは `Authorization: Bearer <token>` ヘッダーで送る。バックエンド
（Render）とフロントエンド（Vercel）はドメインが異なるクロスサイト構成のため、
Cookie方式（SameSite=None）は Safari の ITP（Intelligent Tracking Prevention）に
より既定でブロックされ、iOS の PWA を含む Safari 系ブラウザでログインが機能しない
問題があった。この経緯から、セッション本体はCookieではなくBearerトークンとして
クライアント側（localStorage）で保持する方式に変更している（Issue報告により判明）。
URLクエリには実際のセッションJWTではなく、数十秒で失効し一度しか使えない
「交換コード」のみを載せることで、RFC 9700が禁止する「アクセストークンの
URLクエリでの受け渡し」を回避しつつ、ブラウザ間の互換性を確保する。
"""
import logging
import secrets
import threading
import time
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth import external_login
from app.auth.account_store import upsert_user_token
from app.auth.dependencies import get_session_token
from app.auth.github_oauth import (
    CALLBACK_PATH,
    build_authorize_url,
    exchange_code_for_token,
    get_authenticated_user_login,
)
from app.auth.session import create_session_token, decode_session_token, refresh_session_token
from app.core.config import settings
from app.core.database import get_db
from app.depscan.user_scan import run_depscan_for_user, should_rescan_for_user

logger = logging.getLogger(__name__)

router = APIRouter()

_CALLBACK_PATH = CALLBACK_PATH
_STATE_COOKIE = "gh_oauth_state"

# 交換コード（使い捨て・短命）のインメモリストア: {code: (session_token, expires_at)}。
# Render は WEB_CONCURRENCY=1（単一プロセス）で運用しているため、インメモリで問題ない。
_EXCHANGE_CODE_TTL_SECONDS = 60
_pending_exchange_codes: dict[str, tuple[str, float]] = {}

def _store_exchange_code(session_token: str) -> str:
    """セッションJWTと交換可能な、使い捨ての交換コードを発行する。"""
    now = time.monotonic()
    # ついでに期限切れの古いコードを掃除する
    expired = [c for c, (_, exp) in _pending_exchange_codes.items() if exp < now]
    for c in expired:
        del _pending_exchange_codes[c]

    code = secrets.token_urlsafe(32)
    _pending_exchange_codes[code] = (session_token, now + _EXCHANGE_CODE_TTL_SECONDS)
    return code


def _consume_exchange_code(code: str) -> str | None:
    """交換コードを検証し、対応するセッションJWTを返す（一度使うと失効する）。"""
    entry = _pending_exchange_codes.pop(code, None)
    if entry is None:
        return None
    session_token, expires_at = entry
    if time.monotonic() > expires_at:
        return None
    return session_token


class ExchangeRequest(BaseModel):
    code: str


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
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    code: str = Query(...),
    state: str = Query(...),
    gh_oauth_state: str | None = Cookie(None),
) -> Response:
    if not settings.GITHUB_OAUTH_CLIENT_ID or not settings.GITHUB_OAUTH_CLIENT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="GitHub OAuth is not configured.",
        )
    # 別の機能（MCP サーバーの OAuth 2.1 ログイン等）が登録した流れの state なら、その流れへ任せる
    # （ダッシュボードのログイン用 state はランダム文字列のため、どの流れにも一致しない）
    external = external_login.find(state)
    if external is not None:
        flow, identifier = external
        return flow.complete(db, identifier, code, request)

    if not gh_oauth_state or not secrets.compare_digest(gh_oauth_state, state):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OAuth state.")

    redirect_uri = f"{settings.API_BASE_URL_FOR_OAUTH}{_CALLBACK_PATH}"
    access_token = exchange_code_for_token(
        settings.GITHUB_OAUTH_CLIENT_ID, settings.GITHUB_OAUTH_CLIENT_SECRET, code, redirect_uri,
    )
    username = get_authenticated_user_login(access_token)
    logger.info("DEPSCAN dashboard login: %s", username)

    # ログインのたびにアクセストークンを暗号化して保存する（Issue #227）。
    # 登録済みユーザー自身のリポジトリに対するDEPSCAN/CODESCAN/DEPSOPSの定期実行
    # （app.jobs.user_crawl_runner）が、ログイン中でなくてもこのトークンを使って
    # 実行できるようにするため（従来はオンデマンドスキャン1回にしか使わず、
    # 保存していなかった）
    upsert_user_token(db, username, access_token)

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
    # RFC 9700: アクセストークン（セッションJWT）相当の資格情報をURIクエリパラメータで
    # 渡さない。代わりに数十秒で失効する使い捨ての交換コードのみをURLに載せ、
    # フロントエンドは POST /auth/exchange でこれをJWTと交換する
    exchange_code = _store_exchange_code(session_token)
    redirect_url = f"{settings.FRONTEND_URL.rstrip('/')}/?depscan_code={exchange_code}"
    resp = RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)
    resp.delete_cookie(_STATE_COOKIE)
    return resp


@router.post("/exchange", summary="交換コードをセッションJWTに交換する（使い捨て）")
def exchange(body: ExchangeRequest) -> dict:
    """`/auth/github/callback` が発行した交換コードを検証し、セッションJWTと
    ログインユーザー名を返す。コードは一度使うと失効する。
    """
    session_token = _consume_exchange_code(body.code)
    if session_token is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid, expired, or already-used exchange code.",
        )
    username = decode_session_token(session_token)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid session token.",
        )
    return {"token": session_token, "username": username}


@router.post("/refresh", summary="セッションJWTの有効期間を延長する（スライディング更新）")
def refresh(token: str = Depends(get_session_token)) -> dict:
    """有効なセッションJWTを、有効期間を延長した新しいJWTに交換する。

    ダッシュボードを開いたときに呼ぶ。数時間・数日開かなかっただけでログインが切れないようにする
    （Issue #337）。ログインから上限日数を超えた場合・期限切れ・無効なトークンは 401
    （GitHub で再ログインさせる）。
    """
    new_token = refresh_session_token(token)
    username = decode_session_token(new_token) if new_token else None
    if new_token is None or username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session token.",
        )
    return {"token": new_token, "username": username}
