"""DEPSOPS の PR 判定履歴（`DependabotPrLog`）の保持期間の整理。

履歴は、実行のたびに増える。肥大化を防ぐため、古い行・重複した行・旧方針の行を削除する。
記録と検索を担当する `pr_log_repository.PrLogRepository` とは、責務を分ける
（単一責任。記録の仕組みと、増えすぎた行の整理は、変わる理由が別）。
"""
import logging
from datetime import timedelta

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db_utils import now_utc
from app.depsops.models import DependabotPrLog

logger = logging.getLogger(__name__)


class PrLogRetention:
    """`DependabotPrLog` テーブルの整理（1つの DB セッションに紐づく）。"""

    def __init__(self, db: Session) -> None:
        self._db = db

    def delete_expired(self) -> int:
        """保持期間（DEPSOPS_RETENTION_DAYS）を超えた PR 履歴レコードを削除する。

        Returns:
            削除件数
        """
        cutoff = now_utc() - timedelta(days=settings.DEPSOPS_RETENTION_DAYS)
        deleted = (
            self._db.query(DependabotPrLog)
            .filter(DependabotPrLog.processed_at < cutoff)
            .delete(synchronize_session=False)
        )
        self._db.commit()
        logger.info(
            "DEPSOPS old PR log records deleted: %d (processed_at < %s)", deleted, cutoff.date(),
        )
        return deleted

    def purge_legacy_closed(self) -> int:
        """過去に"closed"として記録されたPRの履歴行を全削除する（解決済みの削除方針への移行用）。

        以前は解消を検知すると"closed"行を追記していたが、現在は解消PRの全行を削除する。
        既に記録されている"closed"行を毎回の実行時に掃除し、マイグレーション無しで
        本番データを新方針へ収束させる。最新状態が"closed"のPRのみが対象で、
        その後再び"flagged"/"merged"になったPRは削除しない。

        Returns:
            削除した行数
        """
        rows = (
            self._db.query(
                DependabotPrLog.id, DependabotPrLog.repo_full_name,
                DependabotPrLog.pr_number, DependabotPrLog.action,
            )
            .order_by(DependabotPrLog.processed_at.desc(), DependabotPrLog.id.desc())
            .all()
        )
        latest: dict[tuple[str, int], str] = {}
        for _id, repo, number, action in rows:
            latest.setdefault((repo, number), action)

        deleted = 0
        for (repo, number), action in latest.items():
            if action != "closed":
                continue
            deleted += (
                self._db.query(DependabotPrLog)
                .filter(
                    DependabotPrLog.repo_full_name == repo,
                    DependabotPrLog.pr_number == number,
                )
                .delete(synchronize_session=False)
            )
        self._db.commit()
        logger.info("DEPSOPS legacy closed PR log records deleted: %d", deleted)
        return deleted

    def collapse_duplicate_flagged(self) -> int:
        """同一PRで同じ内容の"flagged"行が連続している重複を、最新の1行にまとめる。

        以前は「要確認」のPRが毎回の実行で1行ずつ追記されていたため、既存データには
        同じPRの同一内容の行が大量に残っている。直前の行（action問わず）と
        (action="flagged", reason, is_security_update)が同一の"flagged"行について、
        古い側を削除して最新の行だけを残す（冪等）。

        Returns:
            削除した行数
        """
        rows = (
            self._db.query(DependabotPrLog)
            .order_by(
                DependabotPrLog.repo_full_name, DependabotPrLog.pr_number,
                DependabotPrLog.processed_at.asc(), DependabotPrLog.id.asc(),
            )
            .all()
        )
        delete_ids: list[int] = []
        previous: DependabotPrLog | None = None
        for row in rows:
            same_pr = (
                previous is not None
                and previous.repo_full_name == row.repo_full_name
                and previous.pr_number == row.pr_number
            )
            if (
                same_pr
                and previous is not None
                and previous.action == "flagged"
                and row.action == "flagged"
                and previous.reason == row.reason
                and previous.is_security_update == row.is_security_update
            ):
                delete_ids.append(previous.id)
            previous = row

        for start in range(0, len(delete_ids), 500):
            self._db.query(DependabotPrLog).filter(
                DependabotPrLog.id.in_(delete_ids[start:start + 500])
            ).delete(synchronize_session=False)
        self._db.commit()
        logger.info("DEPSOPS duplicate flagged log records collapsed: %d", len(delete_ids))
        return len(delete_ids)

    def cleanup(self) -> None:
        """PR判定履歴の整理（旧"closed"行の削除・重複"flagged"行の集約・保持期間超過分の削除）。"""
        self.purge_legacy_closed()
        self.collapse_duplicate_flagged()
        self.delete_expired()
