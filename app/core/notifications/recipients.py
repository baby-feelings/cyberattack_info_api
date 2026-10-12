"""通知の送信先（登録ユーザーの Slack Webhook）の解決。

KEV/OSV/JVN は特定リポジトリに紐づかないグローバルな脅威情報のため、通知を有効にしている
**全登録ユーザー**へブロードキャストする。DEPSCAN/DEPSOPS/CODESCAN の毎日クロール
（`GITHUB_USERNAME` 自身のリポジトリ対象）は、`GITHUB_USERNAME` 自身が登録した Webhook にのみ
送る（無関係な他ユーザーに baby-feelings 自身のリポジトリの通知が届かないようにするため）。

**エラー通知だけは例外**で、crawler_type に関わらず常に管理者（`GITHUB_USERNAME`）自身の
Webhook にのみ送る（クローラーの内部エラーは運用担当者が対応すべき情報で、無関係なユーザーに
通知してもノイズにしかならないため）。
"""
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.types import CrawlerType

# グローバル（リポジトリに紐づかない）扱いにするクローラー種別。
# それ以外（DEPSCAN/DEPSOPS/CODESCAN）は GITHUB_USERNAME 自身の通知先にのみ送る
GLOBAL_CRAWLER_TYPES: frozenset[str] = frozenset({"KEV", "OSV", "JVN"})


def resolve_recipients(crawler_type: CrawlerType) -> list[str]:
    """クローラー種別から、Slack通知の送信先URL一覧を解決する。

    KEV/OSV/JVN はグローバルな脅威情報のため通知が有効な全登録ユーザーへ、
    DEPSCAN/DEPSOPS/CODESCAN（baby-feelings＝GITHUB_USERNAME自身の毎日クロール）
    は GITHUB_USERNAME 自身が登録したWebhookにのみ送る。
    """
    from app.auth.account_store import list_all_webhooks

    db: Session = SessionLocal()
    try:
        if crawler_type in GLOBAL_CRAWLER_TYPES:
            return list_all_webhooks(db)
        return resolve_admin_recipient(db)
    finally:
        db.close()


def resolve_admin_recipient(db: Session | None = None) -> list[str]:
    """管理者（GITHUB_USERNAME）自身が登録したWebhookのみを返す。

    エラー通知は、検知結果の通知（notify_success等）とは異なりKEV/OSV/JVNの
    ようなグローバル種別でも全登録ユーザーへブロードキャストせず、常に運用担当
    である管理者のSlackにのみ送る（クローラーの内部エラーは各ユーザーが対応
    できる情報ではなく、無関係なユーザーに通知するとノイズ・情報漏洩になるため）。
    """
    from app.auth.account_store import get_webhook_for_user

    owns_session = db is None
    db = db if db is not None else SessionLocal()
    try:
        webhook = get_webhook_for_user(db, settings.GITHUB_USERNAME)
        return [webhook] if webhook else []
    finally:
        if owns_session:
            db.close()
