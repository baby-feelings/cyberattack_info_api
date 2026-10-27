"""言語・実行環境のバージョン監視（RUNTIME）のジョブの組み立て。

1回の実行で、次の2つを行う。

1. 最新版・サポート期限の更新（`eol_client`。endoflife.date と Flutter 公式のリリース情報）
2. 全対象リポジトリの設定ファイルから、使っている版の検出（`detector`）

役割ごとの実装は次にある。

- `detector`: ファイルの内容 → 使っている言語・実行環境（純粋な変換）
- `eol_client`: 最新版・サポート期限の取得
- `repository`: 永続化
- `status`: 使っている版の状態の判定（クロールではなく、閲覧のたびに行う）

毎日 APScheduler から呼ばれる（`app.jobs.scheduler_jobs`）。
"""
import logging

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.crawler_runner import CrawlCounters, CrawlJob
from app.core.github.accounts import list_target_repos
from app.core.github.repo import GitHubRepo
from app.core.github.tree_paths import VENDORED_DIR_SEGMENTS, is_under_excluded_dir
from app.runtimes.detector import DetectedRuntime, detect_runtimes, is_candidate
from app.runtimes.eol_client import fetch_all_releases
from app.runtimes.repository import RepoRuntimeRepository, RuntimeReleaseRepository

logger = logging.getLogger(__name__)

# 1リポジトリあたりに取得する設定ファイル数の上限（過剰な API 呼び出しを防ぐ安全弁）
_MAX_FILES_PER_REPO = 40
# 1ファイルあたりの取得上限サイズ（バイト。巨大な生成物を読まないため）
_MAX_FILE_SIZE = 300_000

# 検出の対象から外すディレクトリ（依存物・生成物・仮想環境）
_EXCLUDED_DIR_SEGMENTS = VENDORED_DIR_SEGMENTS | {".dart_tool", "Pods"}


def detect_repo_runtimes(repo: GitHubRepo, default_branch: str) -> list[DetectedRuntime] | None:
    """リポジトリの設定ファイルから、使っている言語・実行環境を検出する。

    Returns:
        検出結果（何も見つからなければ空）。ファイルツリーを取得できなかった場合は None
        （前回までの内容を残すため、呼び出し側は保存しない）
    """
    try:
        paths = repo.tree(default_branch)
    except httpx.HTTPError as exc:
        logger.warning("RUNTIME: failed to get tree for %s: %s", repo.full_name, exc)
        return None

    candidates = [
        path for path in paths
        if is_candidate(path)
        and not is_under_excluded_dir(path, _EXCLUDED_DIR_SEGMENTS)
    ][:_MAX_FILES_PER_REPO]

    detected: list[DetectedRuntime] = []
    for path in candidates:
        try:
            content = repo.file_content(path)
        except httpx.HTTPError as exc:
            logger.warning("RUNTIME: failed to fetch %s in %s: %s", path, repo.full_name, exc)
            continue
        if len(content) <= _MAX_FILE_SIZE:
            detected.extend(detect_runtimes(path, content))
    return detected


class _RuntimeJob(CrawlJob):
    """RUNTIME の1回分の実行（`CrawlJob` のサブクラス）。

    `CrawlCounters` へのマッピング: inserted=検出した使用中の版の件数、
    updated=更新したリリース情報の件数。
    """

    crawler_type = "RUNTIME"

    def execute(self, db: Session, counters: CrawlCounters) -> None:
        # 1. 最新版・サポート期限（全ての取得元が失敗したときは例外で、クロール失敗にする）
        counters.updated = RuntimeReleaseRepository(db).upsert(fetch_all_releases())

        # 2. 全対象リポジトリの設定ファイルから、使っている版を検出する
        repos = list_target_repos(settings.GITHUB_TOKEN)
        logger.info("RUNTIME: %d target repos to scan", len(repos))
        repository = RepoRuntimeRepository(db)
        for repo_info in repos:
            full_name = repo_info["full_name"]
            repo = GitHubRepo.from_full_name(full_name, settings.GITHUB_TOKEN)
            detected = detect_repo_runtimes(repo, repo_info.get("default_branch") or "main")
            if detected is None:
                continue
            # 1リポジトリの保存失敗で、他のリポジトリの検出を止めない
            try:
                counters.inserted += repository.replace(full_name, detected)
            except Exception as exc:
                logger.error("RUNTIME: failed to save %s: %s", full_name, exc, exc_info=True)

    def after_success(self, counters: CrawlCounters) -> None:
        # 毎日の成功を Slack へ流さない（新しい版・サポート期限の通知は、別途行う）
        logger.info(
            "=== RUNTIME completed: detected=%d, releases=%d ===",
            counters.inserted, counters.updated,
        )


def fetch_and_scan_runtimes(*, force: bool = False) -> tuple[int, int, int]:
    """RUNTIME のメインエントリポイント。APScheduler から毎日呼び出される。

    Args:
        force: True の場合、今日すでに成功実行済みでも強制的に再実行する

    Returns:
        (detected, releases, 0) のタプル（スキップ時は (0, 0, 0)）
    """
    logger.info("=== RUNTIME started ===")
    return _RuntimeJob().run(force=force)  # type: ignore[return-value]
