"""`FindingException` の永続化（登録・解除・一覧・期限の判定）。"""
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.core.db_utils import as_utc
from app.crawler_logs.writer import now_utc
from app.finding_exceptions.matching import active_exceptions
from app.finding_exceptions.models import (
    ENDED_EXPIRED,
    ENDED_REVOKED,
    STATUS_ACCEPTED,
    FindingException,
)


class FindingExceptionRepository:
    """`FindingException` の永続化。"""

    def __init__(self, db: Session) -> None:
        self._db = db

    def upsert_active(
        self, *, kind: str, repo_full_name: str, finding_key: str, status: str,
        reason: str, expires_at: datetime | None, approver: str,
    ) -> FindingException:
        """例外を登録する。同じ検知に有効な例外があれば、新しく作らず内容を更新する。"""
        existing = (
            active_exceptions(self._db, kind)
            .filter(
                FindingException.repo_full_name == repo_full_name,
                FindingException.finding_key == finding_key,
            )
            .first()
        )
        row = existing or FindingException(
            kind=kind, repo_full_name=repo_full_name, finding_key=finding_key,
        )
        row.status = status
        row.reason = reason
        row.expires_at = expires_at
        row.approver = approver
        # 期限を変えたら、「期限の7日前」の通知を、やり直せるようにする
        row.expiry_notified_at = None
        if existing is None:
            self._db.add(row)
        self._db.commit()
        self._db.refresh(row)
        return row

    def get(self, exception_id: int) -> FindingException | None:
        return self._db.get(FindingException, exception_id)

    def end(self, row: FindingException, reason: str = ENDED_REVOKED) -> FindingException:
        """例外を終了する（解除・期限切れ・修正版の公開）。"""
        row.ended_at = now_utc()
        row.ended_reason = reason
        self._db.commit()
        self._db.refresh(row)
        return row

    def find(
        self, *, kind: str | None = None, repo: str | None = None, owner: str | None = None,
        include_ended: bool = False,
    ) -> list[FindingException]:
        """例外の一覧（新しい順）。既定は有効なものだけ。"""
        query = self._db.query(FindingException)
        if not include_ended:
            query = query.filter(FindingException.ended_at.is_(None))
        if kind:
            query = query.filter(FindingException.kind == kind)
        if repo:
            query = query.filter(FindingException.repo_full_name == repo)
        if owner:
            query = query.filter(FindingException.repo_full_name.like(f"{owner}/%"))
        return query.order_by(FindingException.created_at.desc(), FindingException.id.desc()).all()

    def expire_due(self, now: datetime) -> list[FindingException]:
        """期限が切れた有効な例外を終了にする。終了にした例外を返す。"""
        due = [
            row for row in self._db.query(FindingException)
            .filter(FindingException.ended_at.is_(None), FindingException.expires_at.is_not(None))
            .all()
            if row.expires_at is not None and as_utc(row.expires_at) <= now
        ]
        for row in due:
            row.ended_at = now
            row.ended_reason = ENDED_EXPIRED
        self._db.commit()
        return due

    def due_soon(self, now: datetime, days: int) -> list[FindingException]:
        """期限が `days` 日以内で、まだ通知していない有効な受容。通知済みにして返す。"""
        limit = now + timedelta(days=days)
        soon = [
            row for row in self._db.query(FindingException)
            .filter(
                FindingException.ended_at.is_(None),
                FindingException.status == STATUS_ACCEPTED,
                FindingException.expires_at.is_not(None),
                FindingException.expiry_notified_at.is_(None),
            )
            .all()
            if row.expires_at is not None and now < as_utc(row.expires_at) <= limit
        ]
        for row in soon:
            row.expiry_notified_at = now
        self._db.commit()
        return soon

    def active_accepted(self, kind: str) -> list[Any]:
        """有効な受容（修正版の公開で解除する対象）。"""
        return (
            active_exceptions(self._db, kind)
            .filter(FindingException.status == STATUS_ACCEPTED)
            .all()
        )
