"""登録済みユーザー向け定期スキャン（Issue #227）の手動トリガー API ルーター。

POST /admin/user-crawl – GITHUB_USERNAME 以外の登録済みユーザー（Webhook登録済み）
全員分の DEPSCAN/CODESCAN/DEPSOPS をバックグラウンドで実行する。
"""
import logging

from fastapi import APIRouter, Security
from pydantic import BaseModel

from app.core.auth import require_api_key
from app.core.background import run_in_background
from app.core.user_crawl_runner import run_user_crawls_for_all_accounts

logger = logging.getLogger(__name__)

admin_router = APIRouter(tags=["admin"])


class UserCrawlResponse(BaseModel):
    message: str


@admin_router.post(
    "/admin/user-crawl",
    dependencies=[Security(require_api_key)],
    summary="登録済みユーザー向けDEPSCAN/CODESCAN/DEPSOPS手動実行（バックグラウンド）",
    description="GITHUB_USERNAME以外の、Slack Webhookを登録済みの全ユーザーを対象に "
    "DEPSCAN → CODESCAN → DEPSOPS を実行する（X-API-KEY必須）。",
    status_code=202,
)
def trigger_user_crawl() -> UserCrawlResponse:
    logger.info("Manual user crawl triggered via /admin/user-crawl")
    run_in_background("USER_CRAWL", run_user_crawls_for_all_accounts)
    return UserCrawlResponse(message="User crawl started in background")
