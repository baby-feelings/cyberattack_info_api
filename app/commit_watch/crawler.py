"""コミットの監視（COMMITWATCH）のジョブの組み立て（Issue #405）。

リポジトリごとに、既定ブランチの先頭（HEAD）の SHA を記録し、次回、前回の SHA から今の HEAD までの
コミットを `compare` で調べる。見慣れないコミッター・ワークフローの危険な変更だけを、管理者に
Slack で知らせる。初回（基準が無い）は、SHA を記録するだけで、通知しない。
毎日 APScheduler から呼ばれる。

【なぜ時刻ではなく SHA か】コミットの日時は、作者が自由に決められる（過去の日付で push すれば、
「前回の確認以降」の絞り込みをすり抜ける）。SHA の範囲なら、日時を偽っても、見逃さない。
さらに、前回の SHA が今の履歴の祖先でなければ、履歴が書き換えられた（force push）と判断できる。
確認の上限を超えたときも、黙って進めず、「未確認のコミットがある」と知らせる。
対象は、既定ブランチ（他のブランチの push は、見ない）。
"""
import logging
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

# 通知の種類
KIND_COMMIT = "commit"                    # 見慣れないコミッター・危険な変更
KIND_REWRITTEN = "history_rewritten"      # 履歴の書き換え（force push の兆候）
KIND_TRUNCATED = "truncated"              # 確認の上限を超え、一部のコミットは未確認

# 1リポジトリ・1回で内容を調べるコミット数の上限（過剰な API 呼び出しを防ぐ安全弁）
_MAX_COMMITS = 100


def _head_sha(repo: GitHubRepo, branch: str) -> str | None:
    """既定ブランチの先頭の SHA（空のリポジトリ・ブランチが無いときは None）。"""
    with repo.api() as api:
        response = api.get(repo.path(f"/commits/{branch}"))
    if response.status_code in (404, 409):
        return None
    response.raise_for_status()
    return str(response.json()["sha"])


def _compare(repo: GitHubRepo, base: str, head: str) -> dict[str, Any] | None:
    """前回の SHA から今の HEAD までの比較。前回の SHA が存在しない（履歴が消えた）ときは None。"""
    with repo.api() as api:
        response = api.get(
            repo.path(f"/compare/{base}...{head}"), params={"per_page": _MAX_COMMITS},
        )
    if response.status_code == 404:
        return None
    response.raise_for_status()
    return dict(response.json())


def _commit_files(repo: GitHubRepo, sha: str) -> list[dict[str, Any]]:
    """コミットの変更ファイル（差分つき）。"""
    with repo.api() as api:
        response = api.get(repo.path(f"/commits/{sha}"))
    response.raise_for_status()
    return list(response.json().get("files") or [])


def inspect_repo(
    repo: GitHubRepo, base: str, head: str, trusted: set[str], *, require_signature: bool = False,
) -> list[dict[str, Any]]:
    """前回の SHA（`base`）から `head` までのコミットから、通知すべきものを集める。"""
    comparison = _compare(repo, base, head)
    # 前回の SHA が消えた・祖先でない（behind・diverged）＝履歴が書き換えられた
    if comparison is None or comparison.get("status") not in ("ahead", "identical"):
        return [{
            "kind": KIND_REWRITTEN, "repo_full_name": repo.full_name, "sha": head[:7],
            "title": f"前回の確認（{base[:7]}）が、今の履歴に含まれていません",
        }]

    alerts: list[dict[str, Any]] = []
    commits = list(comparison.get("commits") or [])[:_MAX_COMMITS]
    for commit in commits:
        files = _commit_files(repo, commit["sha"])
        risky = analysis.find_risky_changes(files)
        trusted_author = analysis.is_trusted(commit, trusted, require_signature=require_signature)
        # 自分のふつうの変更（危険な内容を含まない）では、通知しない
        if trusted_author and not risky:
            continue
        alerts.append({
            "kind": KIND_COMMIT, "repo_full_name": repo.full_name, "sha": commit["sha"][:7],
            "url": commit.get("html_url", ""),
            "author": analysis.author_login(commit) or "（アカウントに紐づかない）",
            "title": analysis.commit_title(commit), "verified": analysis.is_verified(commit),
            "untrusted": not trusted_author,
            "touches_workflow": analysis.touches_workflow(files),
            "risky": [
                {"file": r.file, "description": r.description, "excerpt": r.excerpt} for r in risky
            ],
        })
    # 確認の上限を超えたときは、黙って進めず、知らせる
    total = int(comparison.get("total_commits") or 0)
    if total > len(commits):
        alerts.append({
            "kind": KIND_TRUNCATED, "repo_full_name": repo.full_name, "sha": head[:7],
            "title": f"コミットが{total}件あり、先頭の{len(commits)}件だけを確認しました",
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
        for repo_info in list_target_repos(settings.GITHUB_TOKEN):
            full_name = repo_info["full_name"]
            repo = GitHubRepo.from_full_name(full_name, settings.GITHUB_TOKEN)
            state = db.query(CommitWatchState).filter_by(repo_full_name=full_name).first()
            # 1リポジトリの失敗では、そのリポジトリを飛ばして続ける（基準の SHA は、進めない）
            try:
                head = _head_sha(repo, repo_info.get("default_branch") or "main")
                if head is None:
                    continue
                if state is not None and state.last_sha != head:
                    self.alerts.extend(inspect_repo(
                        repo, state.last_sha, head, trusted,
                        require_signature=settings.COMMITWATCH_REQUIRE_SIGNATURE,
                    ))
            except httpx.HTTPError as exc:
                logger.warning("COMMITWATCH: %s failed: %s", full_name, exc)
                continue
            if state is None:
                # 初回は、基準の SHA だけを記録する（過去のコミットは、通知しない）
                db.add(CommitWatchState(
                    repo_full_name=full_name, last_sha=head, checked_at=now_utc(),
                ))
            else:
                state.last_sha, state.checked_at = head, now_utc()
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
