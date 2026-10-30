"""コミットの監視（COMMITWATCH）のジョブの組み立て（Issue #405）。

リポジトリごとに、前回の確認以降のコミットを調べ、見慣れないコミッター・ワークフローの危険な変更だけを、
管理者に Slack で知らせる。初回（基準が無い）は、基準の時刻を記録するだけで、通知しない
（過去のコミットが、すべて「新しい」ことになるため）。毎日 APScheduler から呼ばれる。
"""
import logging
from datetime import datetime
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.commit_watch import analysis
from app.commit_watch.models import CommitWatchState
from app.core.config import settings
from app.core.crawler_runner import CrawlCounters, CrawlJob
from app.core.github.accounts import list_target_repos
from app.core.github.repo import GitHubRepo
from app.core.notifications.commit_watch import CommitWatchNotifier
from app.crawler_logs.writer import now_utc

logger = logging.getLogger(__name__)

_PER_PAGE = 100
# 1リポジトリ・1回で調べるコミット数の上限（過剰な API 呼び出しを防ぐ安全弁）
_MAX_COMMITS = 100


def _list_commits(
    repo: GitHubRepo, since: datetime, path: str | None = None,
) -> list[dict[str, Any]]:
    params: dict[str, Any] = {"since": since.isoformat(), "per_page": _PER_PAGE}
    if path:
        params["path"] = path
    with repo.api() as api:
        response = api.get(repo.path("/commits"), params=params)
    if response.status_code == 409:      # 空のリポジトリ
        return []
    response.raise_for_status()
    return list(response.json())[:_MAX_COMMITS]


def _commit_detail(repo: GitHubRepo, sha: str) -> dict[str, Any]:
    with repo.api() as api:
        response = api.get(repo.path(f"/commits/{sha}"))
    response.raise_for_status()
    return dict(response.json())


def inspect_repo(repo: GitHubRepo, since: datetime, trusted: set[str]) -> list[dict[str, Any]]:
    """前回の確認以降のコミットから、通知すべきもの（見慣れないコミッター・危険な変更）を集める。"""
    commits = _list_commits(repo, since)
    workflow_path = analysis.WORKFLOW_PREFIX.rstrip("/")
    workflow_shas = {c["sha"] for c in _list_commits(repo, since, workflow_path)}
    alerts: list[dict[str, Any]] = []
    for commit in commits:
        sha = commit["sha"]
        trusted_author = analysis.is_trusted(commit, trusted)
        risky = (
            analysis.find_risky_changes(_commit_detail(repo, sha).get("files") or [])
            if sha in workflow_shas else []
        )
        # 自分のふつうの変更（危険な内容を含まない）では、通知しない
        if trusted_author and not risky:
            continue
        alerts.append({
            "repo_full_name": repo.full_name, "sha": sha[:7], "url": commit.get("html_url", ""),
            "author": analysis.author_login(commit) or "（アカウントに紐づかない）",
            "title": analysis.commit_title(commit), "verified": analysis.is_verified(commit),
            "untrusted": not trusted_author, "touches_workflow": sha in workflow_shas,
            "risky": [
                {"file": r.file, "description": r.description, "excerpt": r.excerpt} for r in risky
            ],
        })
    return alerts


class _CommitWatchJob(CrawlJob):
    """COMMITWATCH の1回分の実行。

    `CrawlCounters` へのマッピング: inserted=確認したリポジトリ数、deleted=通知する変更の件数。
    """

    crawler_type = "COMMITWATCH"

    def __init__(self) -> None:
        self.alerts: list[dict[str, Any]] = []

    def execute(self, db: Session, counters: CrawlCounters) -> None:
        trusted = analysis.trusted_logins(settings.GITHUB_USERNAME, settings.TRUSTED_COMMITTERS)
        started = now_utc()
        for repo_info in list_target_repos(settings.GITHUB_TOKEN):
            full_name = repo_info["full_name"]
            state = db.query(CommitWatchState).filter_by(repo_full_name=full_name).first()
            if state is not None:
                # 1リポジトリの失敗では、そのリポジトリを飛ばして続ける（基準の時刻は、進めない）
                try:
                    repo = GitHubRepo.from_full_name(full_name, settings.GITHUB_TOKEN)
                    self.alerts.extend(inspect_repo(repo, state.checked_at, trusted))
                except httpx.HTTPError as exc:
                    logger.warning("COMMITWATCH: %s failed: %s", full_name, exc)
                    continue
                state.checked_at = started
            else:
                # 初回は、基準の時刻だけを記録する（過去のコミットは、通知しない）
                db.add(CommitWatchState(repo_full_name=full_name, checked_at=started))
            db.commit()
            counters.inserted += 1
        counters.deleted = len(self.alerts)

    def after_success(self, counters: CrawlCounters) -> None:
        logger.info(
            "=== COMMITWATCH completed: repos=%d, alerts=%d ===",
            counters.inserted, counters.deleted,
        )
        # 通知の失敗で、監視を失敗にしない
        try:
            CommitWatchNotifier(self.alerts).send()
        except Exception as exc:
            logger.error("COMMITWATCH: failed to notify: %s", exc, exc_info=True)

    def result(self, counters: CrawlCounters) -> tuple[int, ...]:
        return counters.inserted, counters.deleted, 0


def fetch_and_watch_commits(*, force: bool = False) -> tuple[int, int, int]:
    """COMMITWATCH のメインエントリポイント。APScheduler から毎日呼び出される。

    Returns:
        (repos, alerts, 0) のタプル（スキップ時は (0, 0, 0)）
    """
    logger.info("=== COMMITWATCH started ===")
    return _CommitWatchJob().run(force=force)  # type: ignore[return-value]
