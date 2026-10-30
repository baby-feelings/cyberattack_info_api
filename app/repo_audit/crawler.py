"""リポジトリの設定の監査（REPOAUDIT）のジョブの組み立て（Issue #398）。

全対象リポジトリの設定を点検し、スコアと各項目の判定、前回からの変化（デプロイキー・Webhook・共同編集者）を
保存する。変化があったときは、管理者に Slack で知らせる。毎日 APScheduler から呼ばれる。
"""
import logging
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.crawler_runner import CrawlCounters, CrawlJob
from app.core.github.accounts import list_target_repos
from app.core.github.repo import GitHubRepo
from app.core.notifications.repo_audit import RepoAuditChangeNotifier
from app.crawler_logs.writer import now_utc
from app.repo_audit import checks as audit_checks
from app.repo_audit.collector import collect, snapshot_of
from app.repo_audit.models import RepoAudit

logger = logging.getLogger(__name__)


def audit_repo(db: Session, repo_info: dict[str, Any]) -> list[dict[str, str]]:
    """1リポジトリを点検して保存する。前回からの変化を返す（取得に失敗したら、保存せず例外）。"""
    full_name = repo_info["full_name"]
    repo = GitHubRepo.from_full_name(full_name, settings.GITHUB_TOKEN)
    raw = collect(repo, repo_info.get("default_branch") or "main")
    results = audit_checks.evaluate(raw)
    snapshot = snapshot_of(raw)

    row = db.query(RepoAudit).filter_by(repo_full_name=full_name).first()
    changes = audit_checks.diff_snapshot(row.snapshot if row else None, snapshot)
    if row is None:
        row = RepoAudit(repo_full_name=full_name)
        db.add(row)
    row.score = audit_checks.score(results)
    row.checks = audit_checks.to_dicts(results)
    row.snapshot = snapshot
    row.changes = changes
    row.audited_at = now_utc()
    db.commit()
    return changes


class _RepoAuditJob(CrawlJob):
    """REPOAUDIT の1回分の実行。

    `CrawlCounters` へのマッピング: inserted=点検したリポジトリ数、
    updated=設定に不備（ng）があるリポジトリ数、deleted=変化（追加・削除）の件数。
    """

    crawler_type = "REPOAUDIT"

    def __init__(self) -> None:
        self.changes: dict[str, list[dict[str, str]]] = {}

    def execute(self, db: Session, counters: CrawlCounters) -> None:
        for repo_info in list_target_repos(settings.GITHUB_TOKEN):
            # 1リポジトリの失敗で、他のリポジトリの点検を止めない
            try:
                changes = audit_repo(db, repo_info)
            except httpx.HTTPError as exc:
                logger.warning("REPOAUDIT: %s failed: %s", repo_info["full_name"], exc)
                continue
            counters.inserted += 1
            if changes:
                self.changes[repo_info["full_name"]] = changes
                counters.deleted += len(changes)
        counters.updated = sum(
            1 for row in db.query(RepoAudit)
            if any(c["status"] == audit_checks.NG for c in row.checks)
        )

    def after_success(self, counters: CrawlCounters) -> None:
        logger.info(
            "=== REPOAUDIT completed: repos=%d, with_issues=%d, changes=%d ===",
            counters.inserted, counters.updated, counters.deleted,
        )
        # 変化（新しいデプロイキー・Webhook・共同編集者など）は、乗っ取りの兆候にもなるため
        # 知らせる。
        # 通知の失敗で、監査を失敗にしない
        try:
            RepoAuditChangeNotifier(self.changes).send()
        except Exception as exc:
            logger.error("REPOAUDIT: failed to notify: %s", exc, exc_info=True)

    def result(self, counters: CrawlCounters) -> tuple[int, ...]:
        return counters.inserted, counters.deleted, counters.updated


def fetch_and_audit_repos(*, force: bool = False) -> tuple[int, int, int]:
    """REPOAUDIT のメインエントリポイント。APScheduler から毎日呼び出される。

    Returns:
        (repos, changes, with_issues) のタプル（スキップ時は (0, 0, 0)）
    """
    logger.info("=== REPOAUDIT started ===")
    return _RepoAuditJob().run(force=force)  # type: ignore[return-value]
