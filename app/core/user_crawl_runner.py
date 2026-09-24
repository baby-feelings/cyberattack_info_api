"""登録済みユーザー（GITHUB_USERNAME以外）自身のリポジトリに対する DEPSCAN/
CODESCAN/DEPSOPS の定期実行オーケストレーション（Issue #227）。

baby-feelings（GITHUB_USERNAME）自身の毎日クロールは環境変数駆動のまま変更せず、
このモジュールは「ダッシュボードにログインし、かつ Slack Webhook を登録して
通知を有効にしている、GITHUB_USERNAME 以外のユーザー」のみを対象にする
（Webhook未登録のユーザーに対して、通知先が無いままDEPSOPSの自動マージのような
リポジトリを変更する操作を行うのは想定外の驚きになるため、Webhook登録をopt-inの
ゲートとして使う）。

APScheduler から `USER_CRAWL_CRON_HOUR_UTC`/`USER_CRAWL_CRON_MINUTE_UTC` で毎日
呼び出されるほか、`POST /admin/user-crawl` から手動実行もできる。
"""
import logging

from sqlalchemy.orm import Session

from app.auth.account_store import decrypt_account_token, list_other_registered_accounts
from app.codescan.user_scan import run_codescan_for_user
from app.core.config import settings
from app.core.database import SessionLocal
from app.depscan.user_scan import run_depscan_for_user
from app.depsops.user_runner import run_dependabot_ops_for_user

logger = logging.getLogger(__name__)


def run_user_crawls_for_all_accounts() -> int:
    """登録済みの全ユーザー（GITHUB_USERNAME以外、Webhook登録済み）に対し、
    DEPSCAN → CODESCAN → DEPSOPS を順に実行する。

    1ユーザーの失敗が他ユーザーの処理を止めないよう、ユーザー単位で例外を握りつぶす。

    Returns:
        処理したユーザー数
    """
    logger.info("=== User crawl (DEPSCAN/CODESCAN/DEPSOPS for registered users) started ===")
    db: Session = SessionLocal()
    try:
        accounts = list_other_registered_accounts(db, settings.GITHUB_USERNAME)
    finally:
        db.close()

    targets = [
        a for a in accounts
        if a.notifications_enabled and a.slack_webhook_url
    ]
    logger.info("User crawl: %d registered account(s) with an active webhook", len(targets))

    processed = 0
    for account in targets:
        username = account.github_username
        webhook_url = account.slack_webhook_url
        token = decrypt_account_token(account)
        if token is None or webhook_url is None:
            logger.warning(
                "User crawl: skipping %s (token could not be decrypted)", username,
            )
            continue

        try:
            run_depscan_for_user(username, token)
            run_codescan_for_user(username, token)
            run_dependabot_ops_for_user(username, token, webhook_url)
            processed += 1
        except Exception as exc:
            logger.error("User crawl: failed for %s: %s", username, exc, exc_info=True)

    logger.info("=== User crawl completed: %d account(s) processed ===", processed)
    return processed
