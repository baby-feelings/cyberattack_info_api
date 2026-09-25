"""削除済みリポジトリのデータ削除（Issue #228）の手動トリガー API ルーター。

POST /admin/repo-cleanup – baby-feelings（GITHUB_USERNAME）向けに、GitHub上で
削除済みと確認できたリポジトリのDEPSCAN/CODESCAN/DEPSOPSデータをバックグラウンドで削除する。
"""
import logging

from fastapi import APIRouter, Security
from pydantic import BaseModel

from app.core.auth import require_api_key
from app.core.background import run_in_background
from app.core.repo_cleanup import run_repo_cleanup

logger = logging.getLogger(__name__)

admin_router = APIRouter(tags=["admin"])


class RepoCleanupResponse(BaseModel):
    message: str


@admin_router.post(
    "/admin/repo-cleanup",
    dependencies=[Security(require_api_key)],
    summary="削除済みリポジトリのDEPSCAN/CODESCAN/DEPSOPSデータ削除を手動実行（バックグラウンド）",
    description="GitHub上で削除済みと確認できたリポジトリのデータのみを削除する"
    "（X-API-KEY必須）。アーカイブ化・可視性変更のみのリポジトリは対象外。",
    status_code=202,
)
def trigger_repo_cleanup() -> RepoCleanupResponse:
    logger.info("Manual repo cleanup triggered via /admin/repo-cleanup")
    run_in_background("CLEANUP", run_repo_cleanup)
    return RepoCleanupResponse(message="Repo cleanup started in background")
