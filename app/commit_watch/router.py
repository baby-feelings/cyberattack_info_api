"""コミットの監視の管理 API（手動実行。Issue #405）。

結果は Slack の通知で確認する（一覧の API は、持たない。
通知したコミットの内容を、DB に溜めないため）。
"""
from fastapi import APIRouter, Query, Security

from app.auth.api_key import require_api_key
from app.commit_watch.crawler import fetch_and_watch_commits
from app.core.background import run_in_background

admin_router = APIRouter(tags=["admin"])


@admin_router.post(
    "/admin/commit-watch-crawl", dependencies=[Security(require_api_key)], status_code=202,
    summary="コミットの監視（見慣れないコミッター・ワークフローの危険な変更）を手動実行",
    description="前回の確認以降のコミットを調べ、通常と違うものを管理者の Slack に知らせる処理を"
    "バックグラウンドで開始する（X-API-KEY 必須）。",
)
def trigger_commit_watch(
    force: bool = Query(False, description="今日すでに成功実行済みでも強制的に再実行する"),
) -> dict:
    run_in_background("COMMITWATCH", lambda: fetch_and_watch_commits(force=force))
    return {"message": "Commit watch started in background"}
