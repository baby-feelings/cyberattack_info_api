"""GitHub Projects への自動追加（PROJSYNC）の管理用 API ルーター。

POST /admin/project-sync-crawl – 手動実行（バックグラウンド。X-API-KEY 必須）
"""
from fastapi import APIRouter, Query, Security

from app.auth.api_key import require_api_key
from app.core.runner.background import run_in_background
from app.project_sync.crawler import sync_project_items

admin_router = APIRouter(tags=["admin"])


@admin_router.post(
    "/admin/project-sync-crawl", dependencies=[Security(require_api_key)], status_code=202,
    summary="GitHub Projects への Issue・PR の追加を手動実行（バックグラウンド）",
)
def trigger_project_sync(
    force: bool = Query(False, description="今日すでに成功実行済みでも強制的に再実行する"),
) -> dict:
    run_in_background("PROJSYNC", lambda: sync_project_items(force=force))
    return {"message": "Project sync started in background"}
