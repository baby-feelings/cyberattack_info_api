"""DEPSOPS の PR 判定履歴（`DependabotPrLog`）の永続化を担当するリポジトリ。

判定ロジック（`pr_judge`）・走査の組み立て（`runner`）から DB 操作を切り離す
（関心の分離）。履歴の記録・解消済み PR の検出と削除・肥大化対策の掃除をここに集約する。
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.depsops.models import DependabotPrLog

logger = logging.getLogger(__name__)


class PrLogRepository:
    """`DependabotPrLog` テーブルの記録・検索・掃除（1つの DB セッションに紐づく）。"""

    def __init__(self, db: Session) -> None:
        self._db = db

    def record(
        self,
        merged: list[dict[str, Any]],
        flagged: list[dict[str, Any]],
        processed_at: datetime,
        resolved: list[dict[str, Any]] | None = None,
    ) -> None:
        """判定した PR を1件1行で DependabotPrLog に記録し、解決済みPRの履歴を削除する。

        ダッシュボードで「要確認」PR の一覧・理由を後から確認できるようにするための
        履歴テーブル。Slack 通知（実行時点のスナップショットのみ）とは別に保持する。
        """
        for item in merged:
            self._db.add(DependabotPrLog(
                repo_full_name=item["repo_full_name"],
                pr_number=item["pr_number"],
                title=item["title"],
                action="merged",
                reason=None,
                is_security_update=item.get("is_security_update"),
                compatibility_badge_url=item.get("compatibility_badge_url"),
                processed_at=processed_at,
            ))
        for item in flagged:
            # 同じ理由で「要確認」のまま続くPRは毎日行を追記せず、既存行の判定日時を更新する
            # （理由・セキュリティ判定が変わった場合のみ新しい行として履歴に残す）
            latest = (
                self._db.query(DependabotPrLog)
                .filter(
                    DependabotPrLog.repo_full_name == item["repo_full_name"],
                    DependabotPrLog.pr_number == item["pr_number"],
                )
                .order_by(DependabotPrLog.processed_at.desc(), DependabotPrLog.id.desc())
                .first()
            )
            if (
                latest is not None
                and latest.action == "flagged"
                and latest.reason == item.get("reason")
                and latest.is_security_update == item.get("is_security_update")
            ):
                latest.title = item["title"]
                latest.compatibility_badge_url = item.get("compatibility_badge_url")
                latest.processed_at = processed_at
                continue
            self._db.add(DependabotPrLog(
                repo_full_name=item["repo_full_name"],
                pr_number=item["pr_number"],
                title=item["title"],
                action="flagged",
                reason=item.get("reason"),
                is_security_update=item.get("is_security_update"),
                compatibility_badge_url=item.get("compatibility_badge_url"),
                processed_at=processed_at,
            ))
        # 解決済み（DEPSOPS外の要因で解消）のPRは履歴を残さず、そのPRの全行を削除する。
        # 「未解決」件数は最新状態が"flagged"のPRのみを数えるため集計は変わらず、
        # 毎日追記される"flagged"行の肥大化も解消できる（自動マージ"merged"の記録は残す）
        for item in resolved or []:
            self._db.query(DependabotPrLog).filter(
                DependabotPrLog.repo_full_name == item["repo_full_name"],
                DependabotPrLog.pr_number == item["pr_number"],
            ).delete(synchronize_session=False)
        self._db.commit()

    def find_resolved_flagged(
        self, full_name: str, open_pr_numbers: set[int],
    ) -> list[dict[str, Any]]:
        """当該リポジトリで直近の判定が "flagged"（要確認）のまま記録されているが、
        今回のスキャンで Open な Dependabot PR 一覧に含まれなくなった PR を検出する。

        Dependabot自身による自動クローズ（後続のgrouped PRに統合される等）や、
        人手によるマージ・クローズなど、DEPSOPSの関知しないところで PR が解消される
        ケースがある。これを検知して"closed"として記録しないと、ダッシュボードの
        「未解決」件数（最新状態が"flagged"のPR数）が実態と乖離したまま残り続ける
        （典型例: CI未設定のリポジトリでは全PRが機械的にflaggedになるため、後から
        手動マージやDependabotの自動クローズで解消されても「未解決」表示が減らない）。
        """
        rows = (
            self._db.query(DependabotPrLog)
            .filter(DependabotPrLog.repo_full_name == full_name)
            .order_by(DependabotPrLog.processed_at.desc())
            .all()
        )
        latest_by_pr: dict[int, DependabotPrLog] = {}
        for row in rows:
            latest_by_pr.setdefault(row.pr_number, row)

        return [
            {
                "repo_full_name": full_name,
                "pr_number": row.pr_number,
                "title": row.title,
                "is_security_update": row.is_security_update,
                "compatibility_badge_url": row.compatibility_badge_url,
                "reason": "Dependabotの自動クローズや手動マージ等、DEPSOPS外の要因で解消済み",
            }
            for pr_number, row in latest_by_pr.items()
            if row.action == "flagged" and pr_number not in open_pr_numbers
        ]

    def delete_expired(self) -> int:
        """保持期間（DEPSOPS_RETENTION_DAYS）を超えた PR 履歴レコードを削除する。

        Returns:
            削除件数
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=settings.DEPSOPS_RETENTION_DAYS)
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
