"""例外の期限・修正版の公開の確認（毎日の定期ジョブ。Issue #403）。

- 修正版が公開された受容（依存ライブラリ）を、自動で解除して通知する
- 期限が切れた例外を終了にし、再び有効な検知として通知・Issue に示す
- 受容の期限の `EXCEPTION_EXPIRY_NOTICE_DAYS` 日前に、一度だけ通知する
通知・Issue は、管理者（`GITHUB_USERNAME`）自身のリポジトリの分のみ（他の登録ユーザーには、
本人の Webhook・トークンの仕組みが別に要るため、状態の更新だけを行う）。
"""
import logging
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.notifications.exception_notices import ExceptionNoticeNotifier
from app.crawler_logs.writer import now_utc
from app.finding_exceptions.issue_sync import is_admin_repo, refile_issues
from app.finding_exceptions.matching import findings_for
from app.finding_exceptions.models import ENDED_FIX_AVAILABLE, KIND_DEPENDENCY, FindingException
from app.finding_exceptions.repository import FindingExceptionRepository

logger = logging.getLogger(__name__)


def _label(exc: FindingException) -> str:
    """通知に出す、検知の見出し（キーの区切りを、読みやすく置き換える）。"""
    return exc.finding_key.replace("|", " / ")


def _notice(exc: FindingException) -> dict[str, Any]:
    return {
        "repo_full_name": exc.repo_full_name,
        "label": _label(exc),
        "reason": exc.reason,
        "expires_at": exc.expires_at.date().isoformat() if exc.expires_at else None,
    }


def _fix_published(db: Session, exc: FindingException) -> bool:
    """受容した依存ライブラリの検知に、修正版が公開されたか。"""
    return any(row.fixed_versions for row in findings_for(db, exc))


def run_exception_lifecycle(now: datetime | None = None) -> dict[str, int]:
    """例外の終了判定と通知を行う。件数（fixed・expired・soon）を返す。"""
    now = now or now_utc()
    db = SessionLocal()
    try:
        repo = FindingExceptionRepository(db)
        fixed = [
            exc for exc in repo.active_accepted(KIND_DEPENDENCY) if _fix_published(db, exc)
        ]
        for exc in fixed:
            repo.end(exc, ENDED_FIX_AVAILABLE)
        # 期限が切れても、検知が既に解決していれば、知らせることが無い
        expired = [e for e in repo.expire_due(now) if findings_for(db, e)]
        soon = [e for e in repo.due_soon(now, settings.EXCEPTION_EXPIRY_NOTICE_DAYS)
                if findings_for(db, e)]

        reopened = [e for e in (*fixed, *expired) if is_admin_repo(e.repo_full_name)]
        refile_issues(db, reopened)
        notices = {
            "fixed": [_notice(e) for e in fixed if is_admin_repo(e.repo_full_name)],
            "expired": [_notice(e) for e in expired if is_admin_repo(e.repo_full_name)],
            "soon": [_notice(e) for e in soon if is_admin_repo(e.repo_full_name)],
        }
    finally:
        db.close()

    ExceptionNoticeNotifier(notices).send()
    counts = {key: len(items) for key, items in notices.items()}
    logger.info("exception lifecycle: %s", counts)
    return counts
