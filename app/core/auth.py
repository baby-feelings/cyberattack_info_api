"""API キー認証モジュール。
X-API-KEY ヘッダーによるシンプルな固定キー認証を提供する。
個人開発・限定用途のため、シンプルな実装を採用する（YAGNI）。
"""
import hmac
import logging

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app.core.config import settings

logger = logging.getLogger(__name__)

# X-API-KEY ヘッダーを読み取る Security スキーム
_api_key_header = APIKeyHeader(name="X-API-KEY", auto_error=False)


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
