"""ログイン中ユーザー自身のアカウント情報（スキャン進捗・Slack通知設定）の API ルーター。

GET            /auth/scan-status           – オンデマンドスキャンの進捗
GET/PUT/DELETE /auth/notification-settings – Slack Webhook 通知の登録・解除（Issue #227）
"""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth.account_store import clear_slack_webhook, get_account, set_slack_webhook
from app.auth.dependencies import get_current_username
from app.core.database import get_db
from app.core.notifications.slack import is_valid_slack_webhook_url
from app.core.notifications.webhook_test import send_test_notification
from app.depscan.user_scan import get_user_scan_status

router = APIRouter()


@router.get("/scan-status", summary="ログイン中ユーザーのオンデマンドスキャン進捗を取得")
def scan_status(
    db: Annotated[Session, Depends(get_db)],
    username: Annotated[str, Depends(get_current_username)],
) -> dict:
    scan = get_user_scan_status(db, username)
    if scan is None:
        return {"username": username, "status": "not_started"}
    return {
        "username": username,
        "status": scan.status,
        "repos_scanned": scan.repos_scanned,
        "started_at": scan.started_at.isoformat(),
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "error_message": scan.error_message,
    }


# ── Slack Webhook 通知登録（Issue #227） ─────────────────────────


class NotificationSettingsIn(BaseModel):
    slack_webhook_url: str


class NotificationSettingsOut(BaseModel):
    slack_webhook_url: str | None
    notifications_enabled: bool


@router.get(
    "/notification-settings",
    summary="ログイン中ユーザーのSlack通知登録状況を取得",
)
def get_notification_settings(
    db: Annotated[Session, Depends(get_db)],
    username: Annotated[str, Depends(get_current_username)],
) -> NotificationSettingsOut:
    account = get_account(db, username)
    if account is None:
        return NotificationSettingsOut(slack_webhook_url=None, notifications_enabled=True)
    return NotificationSettingsOut(
        slack_webhook_url=account.slack_webhook_url,
        notifications_enabled=account.notifications_enabled,
    )


@router.put(
    "/notification-settings",
    summary="Slack Webhookを登録する（テスト送信に成功した場合のみ保存）",
)
def put_notification_settings(
    body: NotificationSettingsIn,
    db: Annotated[Session, Depends(get_db)],
    username: Annotated[str, Depends(get_current_username)],
) -> NotificationSettingsOut:
    if not is_valid_slack_webhook_url(body.slack_webhook_url):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Slack webhook URL (must start with https://hooks.slack.com/).",
        )
    if not send_test_notification(body.slack_webhook_url, username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to send a test notification to this webhook URL. "
            "Please check the URL and try again.",
        )
    try:
        set_slack_webhook(db, username, body.slack_webhook_url)
    except ValueError as exc:
        # 通常到達しない防御的チェック（UserAccount行はログイン時に必ず作成される）
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return NotificationSettingsOut(
        slack_webhook_url=body.slack_webhook_url, notifications_enabled=True,
    )


@router.delete(
    "/notification-settings",
    summary="Slack Webhook登録を解除する",
)
def delete_notification_settings(
    db: Annotated[Session, Depends(get_db)],
    username: Annotated[str, Depends(get_current_username)],
) -> NotificationSettingsOut:
    clear_slack_webhook(db, username)
    return NotificationSettingsOut(slack_webhook_url=None, notifications_enabled=True)
