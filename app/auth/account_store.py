"""`UserAccount`（ログイン済みユーザーのトークン・Slack Webhook登録）の
DB アクセスをまとめたモジュール（Issue #227）。

`app.auth.router`（ログイン時のトークン保存・設定画面API）と
`app.core.user_crawl_runner`（登録済みユーザーの定期実行）の両方から使う。
"""
import logging

from sqlalchemy.orm import Session

from app.auth.models import UserAccount
from app.core.crypto import decrypt_token, encrypt_token

logger = logging.getLogger(__name__)


def upsert_user_token(db: Session, username: str, access_token: str) -> None:
    """ログイン成功のたびに、そのユーザーの GitHub アクセストークンを暗号化して
    保存（新規なら作成、既存なら最新化）する。`TOKEN_ENCRYPTION_KEY` 未設定時は
    ログに警告を残すだけでログイン自体は継続させる（既存のソフトフェイル方針）。
    """
    try:
        encrypted = encrypt_token(access_token)
    except RuntimeError as exc:
        logger.warning("Skipping UserAccount token persistence: %s", exc)
        return

    account = db.query(UserAccount).filter(UserAccount.github_username == username).first()
    if account is None:
        db.add(UserAccount(github_username=username, github_access_token_encrypted=encrypted))
    else:
        account.github_access_token_encrypted = encrypted
    db.commit()


def get_account(db: Session, username: str) -> UserAccount | None:
    return db.query(UserAccount).filter(UserAccount.github_username == username).first()


def set_slack_webhook(db: Session, username: str, webhook_url: str) -> None:
    """指定ユーザーの Slack Webhook URL を登録・上書きし、通知を有効化する。

    ログイン済みユーザーのみがこの画面に到達できる前提（呼び出し元の
    `require_api_key_or_session` 相当の認証チェック済み）のため、
    `UserAccount` 行がまだ無い場合はトークン未取得のプレースホルダー行を
    作らず例外にする（アカウント行はログイン時の `upsert_user_token` が
    必ず先に作成しているはずのため、通常到達しない防御的チェック）。
    """
    account = get_account(db, username)
    if account is None:
        raise ValueError(f"UserAccount not found for {username}; login first.")
    account.slack_webhook_url = webhook_url
    account.notifications_enabled = True
    db.commit()


def clear_slack_webhook(db: Session, username: str) -> None:
    """指定ユーザーの Slack Webhook 登録を解除する（トークン行自体は残す）。"""
    account = get_account(db, username)
    if account is None:
        return
    account.slack_webhook_url = None
    db.commit()


def list_all_webhooks(db: Session) -> list[str]:
    """通知が有効な、登録済み全ユーザーの Webhook URL 一覧を返す
    （KEV/OSV/JVN のようなグローバルな脅威情報の通知先に使う。重複除去済み）。
    """
    rows = (
        db.query(UserAccount.slack_webhook_url)
        .filter(
            UserAccount.notifications_enabled.is_(True),
            UserAccount.slack_webhook_url.is_not(None),
        )
        .all()
    )
    return sorted({url for (url,) in rows if url})


def get_webhook_for_user(db: Session, username: str) -> str | None:
    """指定ユーザー自身のリポジトリに関する通知（DEPSCAN/CODESCAN/DEPSOPS）の
    送信先を返す。未登録・通知オフなら None。
    """
    account = get_account(db, username)
    if account is None or not account.notifications_enabled:
        return None
    return account.slack_webhook_url


def list_other_registered_accounts(db: Session, exclude_username: str) -> list[UserAccount]:
    """GITHUB_USERNAME（毎日クロールの対象アカウント）以外で、トークンが
    保存されている登録済みユーザー一覧を返す（`app.core.user_crawl_runner` が
    定期実行の対象を決めるために使う）。
    """
    return (
        db.query(UserAccount)
        .filter(UserAccount.github_username != exclude_username)
        .all()
    )


def decrypt_account_token(account: UserAccount) -> str | None:
    """アカウント行の暗号化済みトークンを復号する（薄いラッパー、DRY用）。"""
    return decrypt_token(account.github_access_token_encrypted)
