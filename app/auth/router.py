"""`/auth` 配下のルーターを1つにまとめる（実装は責務ごとのモジュールに分かれている）。

- `github_router`  : GitHub ログイン・交換コード
- `mcp_router`     : MCP トークン・OAuth 接続の管理
- `account_router` : スキャン進捗・Slack 通知設定
- `dependencies`   : ログイン中ユーザーの認証（他ドメインのルーターも使う）
"""
from fastapi import APIRouter

from app.auth import account_router, github_router, mcp_router

router = APIRouter(prefix="/auth", tags=["auth"])
router.include_router(github_router.router)
router.include_router(mcp_router.router)
router.include_router(account_router.router)
