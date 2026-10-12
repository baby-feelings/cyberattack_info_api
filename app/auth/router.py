"""`/auth` 配下のログイン関連ルーターを1つにまとめる（実装は責務ごとのモジュールに分かれている）。

- `github_router`  : GitHub ログイン・交換コード
- `account_router` : スキャン進捗・Slack 通知設定
- `dependencies`   : ログイン中ユーザーの認証（他ドメインのルーターも使う）

MCP トークン・OAuth 接続の管理 API（`/auth/mcp-token(s)`・`/auth/oauth-connections`）は
`app.mcp_server.management_router` にある（`auth` は `mcp_server` を知らない）。
"""
from fastapi import APIRouter

from app.auth import account_router, github_router

router = APIRouter(prefix="/auth", tags=["auth"])
router.include_router(github_router.router)
router.include_router(account_router.router)
