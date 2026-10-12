"""OAuth 2.1 認可フローの保存層: 認可リクエスト〜認可コード、GitHub ログインの state（Issue #303）。

流れ（`oauth_authorizations` の1行が進む）:
1. `/authorize` → `create_request`（同意画面と GitHub ログインの待ち）
2. 本人の GitHub ログイン完了 → `complete_request`（本人を紐づけ、認可コードを発行）
3. `/token` → `consume_code`（認可コードは一度しか使えない）

認可コードは保存せず SHA-256 のハッシュだけを持つ。GitHub ログインへ渡す `state` は、
認可リクエストIDを署名付き（JWT）で包んだもの。コールバックは API のドメインが異なる
（nip.io）可能性があり Cookie を使えないため、署名で改ざんと他用途への流用を防ぐ。
"""
import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import jwt
from mcp.server.auth.provider import AuthorizationParams
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.core.config import settings
from app.mcp_server.mcp_token_store import as_utc
from app.mcp_server.models import OAuthAuthorization

# 同意画面と GitHub ログインを済ませるまでの猶予
REQUEST_TTL = timedelta(minutes=10)
# 認可コードの有効期間（発行から `/token` で交換するまで）
CODE_TTL = timedelta(minutes=5)
# アクセストークンの有効期間（リフレッシュトークンは PR3）
ACCESS_TOKEN_TTL = timedelta(hours=1)

_STATE_ALGORITHM = "HS256"
_STATE_AUDIENCE = "cyberattack-info-mcp-oauth-state"


def _now() -> datetime:
    return datetime.now(UTC)


def hash_code(code: str) -> str:
    """認可コードの SHA-256（保存・照合用。十分なエントロピーのため塩は不要）。"""
    return hashlib.sha256(code.encode()).hexdigest()


def create_request(
    db: Session, client_id: str, params: AuthorizationParams, scopes: list[str],
    now: datetime | None = None,
) -> str:
    """認可リクエストを保存し、リクエストIDを返す。期限切れの古い行も掃除する。"""
    now = now or _now()
    purge_expired(db, now)
    request_id = secrets.token_urlsafe(32)
    db.add(OAuthAuthorization(
        id=request_id,
        client_id=client_id,
        redirect_uri=str(params.redirect_uri),
        redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
        state=params.state,
        code_challenge=params.code_challenge,
        scope=" ".join(scopes),
        resource=params.resource,
        created_at=now,
        expires_at=now + REQUEST_TTL,
    ))
    db.commit()
    return request_id


def purge_expired(db: Session, now: datetime | None = None) -> None:
    """期限切れの認可リクエスト・認可コードを削除する。"""
    # synchronize_session=False: SQLite は tz 情報を落とすため、Python 側での比較評価を避ける
    db.execute(
        delete(OAuthAuthorization)
        .where(OAuthAuthorization.expires_at < (now or _now()))
        .execution_options(synchronize_session=False),
    )
    db.commit()


def load_pending(
    db: Session, request_id: str, now: datetime | None = None,
) -> OAuthAuthorization | None:
    """ログイン待ちの（まだ本人が紐づいていない）有効な認可リクエストを返す。"""
    row = db.get(OAuthAuthorization, request_id)
    if row is None or row.username is not None or as_utc(row.expires_at) <= (now or _now()):
        return None
    return row


def discard_request(db: Session, request_id: str) -> None:
    """認可リクエストを破棄する（拒否・失敗時）。"""
    row = db.get(OAuthAuthorization, request_id)
    if row is not None:
        db.delete(row)
        db.commit()


def bind_browser(db: Session, row: OAuthAuthorization) -> str | None:
    """同意画面を最初に開いたブラウザに、この認可リクエストを紐づける。

    未紐づけなら乱数（Cookie に載せる値）を返し、そのハッシュを保存する。すでに紐づいていれば
    None（2つ目のブラウザには Cookie を渡さない）。
    """
    if row.browser_hash is not None:
        return None
    nonce = secrets.token_urlsafe(32)
    row.browser_hash = hash_code(nonce)
    db.commit()
    return nonce


def is_bound_to(row: OAuthAuthorization, nonce: str | None) -> bool:
    """Cookie の乱数が、この認可リクエストを紐づけたブラウザのものか（定数時間で比較）。"""
    if not nonce or row.browser_hash is None:
        return False
    return secrets.compare_digest(row.browser_hash, hash_code(nonce))


def complete_request(
    db: Session, row: OAuthAuthorization, username: str, now: datetime | None = None,
) -> str:
    """本人（GitHub ユーザー名）を紐づけ、認可コード（平文）を発行する。

    同じリクエストでの二重発行を防ぐため、`load_pending` を通った（未完了の）行だけを渡すこと。
    """
    now = now or _now()
    code = secrets.token_urlsafe(32)
    row.username = username
    row.code_hash = hash_code(code)
    row.expires_at = now + CODE_TTL
    db.commit()
    return code


def find_by_code(db: Session, code: str, now: datetime | None = None) -> OAuthAuthorization | None:
    """認可コードに対応する、有効な（期限内の）行を返す。"""
    row = (
        db.query(OAuthAuthorization)
        .filter(OAuthAuthorization.code_hash == hash_code(code))
        .first()
    )
    if row is None or as_utc(row.expires_at) <= (now or _now()):
        return None
    return row


def consume_code(db: Session, code: str) -> bool:
    """認可コードを使用済みにする（行を削除）。使えたら True。

    削除の件数で判定するため、同じコードを同時に2回交換しようとしても片方だけが成功する。
    """
    result = db.execute(
        delete(OAuthAuthorization)
        .where(OAuthAuthorization.code_hash == hash_code(code))
        .execution_options(synchronize_session=False),
    )
    db.commit()
    return result.rowcount == 1  # type: ignore[attr-defined]


def encode_state(request_id: str, now: datetime | None = None) -> str:
    """GitHub ログインへ渡す state（認可リクエストID入りの署名付きJWT）を作る。"""
    now = now or _now()
    payload = {
        "rid": request_id, "aud": _STATE_AUDIENCE, "exp": now + REQUEST_TTL,
        "nonce": uuid.uuid4().hex,
    }
    return jwt.encode(payload, settings.SESSION_SECRET_KEY, algorithm=_STATE_ALGORITHM)


def decode_state(state: str) -> str | None:
    """state が MCP の OAuth ログイン用の正しい署名なら認可リクエストIDを返す。違えば None。

    ダッシュボードのログイン用 state（ランダム文字列）とは、JWT として検証できるかで見分ける。
    """
    if not settings.SESSION_SECRET_KEY:
        return None
    try:
        payload = jwt.decode(
            state, settings.SESSION_SECRET_KEY, algorithms=[_STATE_ALGORITHM],
            audience=_STATE_AUDIENCE,
        )
    except jwt.PyJWTError:
        return None
    rid = payload.get("rid")
    return rid if isinstance(rid, str) and rid else None
