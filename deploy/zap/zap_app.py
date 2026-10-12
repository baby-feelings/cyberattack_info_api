"""ZAP スキャン専用の起動ファイル（使い捨て API コンテナ用。本番では使わない）。

本番と同じ `app.main:app` に、FastAPI の OpenAPI に載らないエンドポイント（/mcp・OAuth 2.1）の定義を
足して `/openapi.json` で公開する。ZAP API Scan は OpenAPI から診断対象を網羅するため
（`app/zapscan/openapi_extras.py`）。
"""
from app.main import app
from app.zapscan.openapi_extras import extend_openapi

extend_openapi(app)
