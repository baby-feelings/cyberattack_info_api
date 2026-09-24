"""API キー認証モジュール。
X-API-KEY ヘッダーによるシンプルな固定キー認証、および X-API-KEY /
GitHub ログインセッション JWT のいずれかを許可する共通認証を提供する。
個人開発・限定用途のため、シンプルな実装を採用する（YAGNI）。
"""
import hmac
import logging

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app.auth.session import decode_session_token
from app.core.config import settings

logger = logging.getLogger(__name__)

# X-API-KEY ヘッダーを読み取る Security スキーム
_api_key_header = APIKeyHeader(name="X-API-KEY", auto_error=False)
# Authorization ヘッダー（`Bearer <session token>`）を読み取る Security スキーム
_bearer_header = APIKeyHeader(name="Authorization", auto_error=False)


def require_api_key(api_key: str = Security(_api_key_header)) -> str:
    """APIキーを検証する依存関数。
    FastAPI の Depends() で各エンドポイントに適用する。

    Args:
        api_key: リクエストの X-API-KEY ヘッダー値

    Returns:
        検証済みの API キー文字列

    Raises:
        HTTPException 403: キーが無効または欠落している場合
    """
    if not api_key or not hmac.compare_digest(api_key, settings.API_KEY):
        logger.warning("Unauthorized API access attempt")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API Key. Set X-API-KEY header.",
        )
    return api_key


def require_public_api_key(api_key: str = Security(_api_key_header)) -> str:
    """読み取り専用エンドポイント向けの認証依存関数。
    管理者用 API_KEY に加えて、公開ダッシュボード用の PUBLIC_API_KEY も許可する。
    /admin/* 等の管理系エンドポイントは require_api_key（API_KEY のみ）で保護されて
    いるため、PUBLIC_API_KEY がブラウザの JS バンドルから漏洩しても管理操作はできない。

    Args:
        api_key: リクエストの X-API-KEY ヘッダー値

    Returns:
        検証済みの API キー文字列

    Raises:
        HTTPException 403: いずれのキーにも一致しない、または欠落している場合
    """
    if api_key:
        if hmac.compare_digest(api_key, settings.API_KEY):
            return api_key
        if settings.PUBLIC_API_KEY and hmac.compare_digest(api_key, settings.PUBLIC_API_KEY):
            return api_key
    logger.warning("Unauthorized public API access attempt")
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid or missing API Key. Set X-API-KEY header.",
    )


def require_api_key_or_session(
    api_key: str = Security(_api_key_header),
    authorization: str = Security(_bearer_header),
) -> str | None:
    """`X-API-KEY`（フルアクセス）または `Authorization: Bearer <セッションJWT>`
    （GitHub ログイン済みの任意のユーザー）のいずれかを要求する共通認証依存関数。

    元々 DEPSCAN（`app.depscan.router._resolve_access`）にのみ実装されていた
    「X-API-KEY または セッション JWT を検証する」というコアロジックをここに
    切り出したもの（DRY原則）。DEPSCAN はこの関数をそのまま `_resolve_access`
    として使い、戻り値（セッション認証時はログインユーザー名）を本人所有
    リポジトリへの絞り込みに使う。CODESCAN（`app.codescan.router`）は戻り値を
    絞り込みには使わず、「ログイン済みかどうか」のみをゲートとして使う
    （CODESCAN の検知結果は特定ユーザーに紐づく情報ではなく、GITHUB_USERNAME
    配下の固定リポジトリ群を対象とするため、DEPSCAN のようなオーナー制限は
    不要。ただし読み取り専用でも GitHub ログインは必須にする）。

    Args:
        api_key: リクエストの X-API-KEY ヘッダー値
        authorization: リクエストの Authorization ヘッダー値（`Bearer <token>`）

    Returns:
        API キー認証の場合は None（絞り込みなし＝フルアクセス）。セッション
        認証の場合はログイン中の GitHub ユーザー名。

    Raises:
        HTTPException 403: いずれの認証にも失敗した場合
    """
    if api_key and hmac.compare_digest(api_key, settings.API_KEY):
        return None
    if authorization and authorization.lower().startswith("bearer "):
        username = decode_session_token(authorization[len("bearer "):].strip())
        if username is not None:
            return username
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid or missing credentials. Provide X-API-KEY or "
        "Authorization: Bearer <session token>.",
    )
