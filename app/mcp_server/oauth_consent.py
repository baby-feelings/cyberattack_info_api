"""OAuth 2.1 の同意画面と、GitHub ログイン完了後の認可コード発行（Issue #303）。

流れ:
1. `/authorize`（SDK）→ `McpOAuthProvider.authorize` が認可リクエストを保存 → `GET /oauth/consent`
2. 同意画面で「許可」→ `POST /oauth/consent`（approve）→ GitHub のログインへ（**スコープなし**。
   本人確認だけで、リポジトリの内容は読まない）
3. GitHub が `/auth/github/callback` へ戻す → 署名付き state で MCP 用と判別 →
   `complete_github_login` が本人を紐づけて認可コードを発行し、クライアントの redirect_uri へ

セキュリティ:
- 認可リクエストIDは推測不能な値で、同意画面の URL にだけ載る。10 分で失効する
- クライアント名は登録時の自己申告（未確認）なので、画面に出す文字列はすべてエスケープし、
  戻り先のホストも併記して判断材料にする
- フレーム埋め込みは全レスポンスの `X-Frame-Options: DENY`（core/security_headers）で防ぐ
- フォームの本文は urlencoded で、依存を増やさないため手で解析する（小さな上限付き）
"""
import base64
import hashlib
import html
import logging
from collections.abc import Callable
from urllib.parse import parse_qs, urlsplit

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from mcp.server.auth.provider import construct_redirect_uri
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.auth.github_oauth import (
    CALLBACK_PATH,
    build_authorize_url,
    exchange_code_for_token,
    get_authenticated_user_login,
)
from app.core.config import settings
from app.mcp_server import oauth_clients, oauth_flow
from app.mcp_server.oauth_provider import CONSENT_PATH, SCOPE

logger = logging.getLogger(__name__)

SessionFactory = Callable[[], Session]

# フォーム本文の上限（認可リクエストID と action だけなので十分小さい）
_MAX_FORM_BYTES = 4096
# 画面に出すクライアント名の最大長（自己申告のため切り詰める）
_MAX_NAME_CHARS = 80

_NO_STORE = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}

# 同意画面を開いたブラウザを識別する Cookie（許可・拒否の送信と、GitHub から戻るコールバックで、
# 同じブラウザかを確認する。10 分で失効）。コールバックは別パス（/auth/github/callback）のため
# パスは / にする（HttpOnly・Secure。GitHub からの遷移は最上位の GET なので SameSite=Lax でも届く）
BROWSER_COOKIE = "mcp_oauth_consent"


# ページのスタイル。CSP では `unsafe-inline` を許さず、この文字列のハッシュだけを許可する
_STYLE = (
    "body{font-family:system-ui,sans-serif;max-width:34rem;margin:2rem auto;"
    "padding:0 1rem;line-height:1.6}"
    "dl{background:#f4f4f5;padding:.8rem 1rem;border-radius:.5rem}"
    "dt{font-weight:600;margin-top:.4rem}dd{margin:0 0 .2rem 0;word-break:break-all}"
    "button{font-size:1rem;padding:.6rem 1.2rem;margin-right:.6rem;border-radius:.4rem;"
    "border:1px solid #888;cursor:pointer}"
    "button.primary{background:#1f6feb;color:#fff;border-color:#1f6feb}"
    ".note{font-size:.9rem;color:#555}"
)
_STYLE_HASH = base64.b64encode(hashlib.sha256(_STYLE.encode()).digest()).decode()

# 外部リソース・スクリプトは一切読み込まない（スタイルは上のハッシュのみ許可）。
# フレーム埋め込みも禁止。form-action は付けない（許可後の GitHub・拒否後の戻り先への
# リダイレクトを妨げるため）
_CSP = (
    f"default-src 'none'; style-src 'sha256-{_STYLE_HASH}'; "
    "frame-ancestors 'none'; base-uri 'none'"
)


def _page(title: str, body: str, status_code: int = 200) -> HTMLResponse:
    """最小限のスタイルだけを持つ HTML ページ（外部リソースは読み込まない）。"""
    doc = f"""<!doctype html>
<html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>{_STYLE}</style></head><body>{body}</body></html>"""
    headers = {**_NO_STORE, "Content-Security-Policy": _CSP}
    return HTMLResponse(doc, status_code=status_code, headers=headers)


def _error_page(message: str, status_code: int = 400) -> HTMLResponse:
    return _page(
        "認可できません",
        f"<h1>認可できません</h1><p>{html.escape(message)}</p>"
        "<p class='note'>接続したいアプリ（Claude Code など）から、"
        "もう一度やり直してください。</p>",
        status_code,
    )


def _redirect_with(row_redirect_uri: str, state: str | None, **params: str | None) -> Response:
    """クライアントの redirect_uri へ、結果（code / error）と state を付けてリダイレクトする。"""
    url = construct_redirect_uri(row_redirect_uri, state=state, **params)
    return RedirectResponse(url, status_code=302, headers=_NO_STORE)


def _consent_page(request_id: str, client_name: str, redirect_host: str) -> HTMLResponse:
    name = html.escape(client_name[:_MAX_NAME_CHARS] or "（名前なし）")
    body = f"""<h1>MCP サーバーへの接続を許可しますか？</h1>
<p>次のアプリが、サイバー攻撃情報 API の MCP サーバーへの接続を求めています。</p>
<dl>
<dt>アプリ名（自己申告・未確認）</dt><dd>{name}</dd>
<dt>認可後の戻り先</dt><dd>{html.escape(redirect_host)}</dd>
<dt>権限</dt><dd>{html.escape(SCOPE)}（読み取り専用）</dd>
</dl>
<p>許可すると GitHub でログインして本人確認を行い、あなた専用の読み取りアクセス（有効 1 時間）が
アプリに渡されます。見えるのは公開の脆弱性情報と、<strong>あなたが所有するリポジトリ</strong>の検知結果だけです。
GitHub のリポジトリの内容には触れません。</p>
<p class="note">心当たりがない場合は「拒否」してください。</p>
<form method="post" action="{html.escape(CONSENT_PATH)}">
<input type="hidden" name="request_id" value="{html.escape(request_id)}">
<button class="primary" type="submit" name="action" value="approve">
許可して GitHub でログイン</button>
<button type="submit" name="action" value="deny">拒否</button>
</form>"""
    return _page("MCP サーバーへの接続を許可", body)


def build_consent_router(session_factory: SessionFactory) -> APIRouter:
    """同意画面のルーター（`GET`=表示、`POST`=許可/拒否）を作る。"""
    router = APIRouter(include_in_schema=False)

    def _show(request_id: str, browser_nonce: str | None) -> Response:
        with session_factory() as db:
            row = oauth_flow.load_pending(db, request_id)
            if row is None:
                return _error_page("認可リクエストが無効か、期限切れです。")
            # 最初に開いたブラウザに紐づける。紐づけ済みなら、同じブラウザ（Cookie 一致）だけ表示
            new_nonce = oauth_flow.bind_browser(db, row)
            if new_nonce is None and not oauth_flow.is_bound_to(row, browser_nonce):
                return _error_page("この認可リクエストは、別のブラウザで開かれています。", 403)
            client = oauth_clients.load_client(db, row.client_id)
            name = (client.client_name if client else None) or ""
            page = _consent_page(request_id, name, urlsplit(row.redirect_uri).netloc)
            if new_nonce is not None:
                max_age = int(oauth_flow.REQUEST_TTL.total_seconds())
                page.set_cookie(
                    BROWSER_COOKIE, new_nonce, max_age=max_age,
                    path="/", httponly=True, secure=True, samesite="lax",
                )
            return page

    def _decide(request_id: str, action: str, browser_nonce: str | None) -> Response:
        with session_factory() as db:
            row = oauth_flow.load_pending(db, request_id)
            if row is None:
                return _error_page("認可リクエストが無効か、期限切れです。")
            # 同意画面を開いたブラウザ以外からの許可・拒否は受け付けない（CSRF・URL の横取り対策）
            if not oauth_flow.is_bound_to(row, browser_nonce):
                return _error_page("同意画面を開いたブラウザから操作してください。", 403)
            if action == "deny":
                redirect_uri, state = row.redirect_uri, row.state
                oauth_flow.discard_request(db, request_id)
                return _redirect_with(redirect_uri, state, error="access_denied")
            if action != "approve":
                return _error_page("不正な操作です。")
            if not settings.GITHUB_OAUTH_CLIENT_ID:
                return _error_page("GitHub ログインが設定されていません。", 503)
            # 本人確認だけ（scope=None）。GitHub のコールバックは既存の /auth/github/callback
            github_url = build_authorize_url(
                settings.GITHUB_OAUTH_CLIENT_ID,
                f"{settings.API_BASE_URL_FOR_OAUTH}{CALLBACK_PATH}",
                oauth_flow.encode_state(request_id),
                scope=None,
            )
            return RedirectResponse(github_url, status_code=303, headers=_NO_STORE)

    @router.get(CONSENT_PATH)
    def consent_page(request: Request, request_id: str = "") -> Response:
        return _show(request_id, request.cookies.get(BROWSER_COOKIE))

    @router.post(CONSENT_PATH)
    async def consent_submit(request: Request) -> Response:
        body = await request.body()
        if len(body) > _MAX_FORM_BYTES:
            return _error_page("リクエストが大きすぎます。", 413)
        form = parse_qs(body.decode("utf-8", errors="replace"))
        request_id = (form.get("request_id") or [""])[0]
        action = (form.get("action") or [""])[0]
        return await run_in_threadpool(
            _decide, request_id, action, request.cookies.get(BROWSER_COOKIE),
        )

    return router


def complete_github_login(
    db: Session, request_id: str, github_code: str, browser_nonce: str | None,
) -> Response:
    """GitHub のコールバック（MCP 用の state）: 本人を確認し、認可コードを発行して戻す。

    ダッシュボードのログイン（`/auth/github/callback` の通常経路）とは別物で、GitHub の
    アクセストークンは保存せず、ユーザー名の取得だけに使って捨てる。

    **同意画面を開いたブラウザからの戻りだけを受け付ける**（Cookie で確認。state は攻撃者も
    自分の認可リクエスト分を入手できるため、これが無いと、被害者に攻撃者の state 付きの GitHub
    認可 URL を踏ませて、被害者の本人確認を攻撃者の認可リクエストに紐づけられる）。
    """
    row = oauth_flow.load_pending(db, request_id)
    if row is None:
        return _error_page("認可リクエストが無効か、期限切れです。")
    if not oauth_flow.is_bound_to(row, browser_nonce):
        return _error_page("同意画面を開いたブラウザから操作してください。", 403)
    redirect_uri, state = row.redirect_uri, row.state
    try:
        access_token = exchange_code_for_token(
            settings.GITHUB_OAUTH_CLIENT_ID, settings.GITHUB_OAUTH_CLIENT_SECRET,
            github_code, f"{settings.API_BASE_URL_FOR_OAUTH}{CALLBACK_PATH}",
        )
        username = get_authenticated_user_login(access_token)
    except (httpx.HTTPError, ValueError, KeyError):
        logger.exception("MCP OAuth: GitHub login failed")
        oauth_flow.discard_request(db, request_id)
        return _redirect_with(redirect_uri, state, error="access_denied")

    code = oauth_flow.complete_request(db, row, username)
    logger.info("MCP OAuth: authorization code issued for %s", username)
    response = _redirect_with(redirect_uri, state, code=code)
    response.delete_cookie(BROWSER_COOKIE, path="/")  # 使い終わった識別 Cookie は消す
    return response
