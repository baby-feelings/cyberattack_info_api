"""API キー認証モジュール。
X-API-KEY ヘッダーによるシンプルな固定キー認証を提供する。
個人開発・限定用途のため、シンプルな実装を採用する（YAGNI）。
"""
import logging
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from app.config import settings

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
    if not api_key or api_key != settings.API_KEY:
        logger.warning("Unauthorized API access attempt")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API Key. Set X-API-KEY header.",
        )
    return api_key
