"""自アプリのコード脆弱性スキャナー（CODESCAN）の走査の組み立て。

GitHub 上の自作アプリ全リポジトリのソースコードを tarball で取得し、Semgrep
（`p/security-audit` + `p/secrets`）と gitleaks（Issue #219）で静的解析する。DEPSCAN
（依存ライブラリの既知脆弱性）とは異なる検知種別として、自アプリのコード自体に潜む脆弱性パターン（SQLi・ハードコード認証情報・XSS等）を検知する。

このモジュールは「どのリポジトリを、どの順で検査するか」の組み立てだけを担う。役割ごとの実装は次にある。

- `archive.RepoArchive`: tarball の安全な展開と一時ディレクトリの管理
- `scanners.Scanner`（`SemgrepScanner` / `GitleaksScanner`）: ツールの実行と出力のレコード化
- `repository.CodeFindingRepository`: 検知結果の永続化（Upsert・解決済み化・保持期間超過の削除）

対象リポジトリ一覧は DEPSCAN と同じ（`GITHUB_USERNAME` 配下、fork・archived 除外）ため
`app.core.github.accounts.list_target_repos` を共有する。オーケストレーションは KEV/OSV/JVN と同じ
`app.core.crawler_runner.run_crawler`（Template Method）+ `CrawlCounters` を使う。
APScheduler から毎日呼び出される。
"""
import json
import logging
import subprocess
import tarfile
from collections.abc import Sequence
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.codescan.archive import RepoArchive
from app.codescan.issue_management import file_github_issues
from app.codescan.repository import CodeFindingRepository
from app.codescan.scanners import Scanner, default_scanners
from app.core.config import settings
from app.core.crawler_runner import CrawlCounters, run_crawler
from app.core.github.accounts import list_target_repos
from app.core.github.repo import GitHubRepo

logger = logging.getLogger(__name__)

# 1リポジトリの検査で起こりうる失敗（API 失敗・ツールのタイムアウト・展開失敗・出力の解析失敗）。
# 呼び出し側はこれらをリポジトリ単位で捕捉し、他のリポジトリの検査は続ける
SCAN_ERRORS: tuple[type[BaseException], ...] = (
    httpx.HTTPError, subprocess.TimeoutExpired, tarfile.TarError, json.JSONDecodeError, OSError,
)


def scan_repo(
    full_name: str, branch: str, token: str, scanners: Sequence[Scanner] | None = None,
) -> list[dict[str, Any]]:
    """1リポジトリを tarball 取得 → 展開 → 各スキャナーで検査 → レコード化する。

    一時ディレクトリは検査完了後（例外発生時を含む）に確実に削除される。スキャナーは互いに独立して
    例外を捕捉し、どれかが失敗・タイムアウトしても他の結果は活かす（1つの try/except で全部を
    囲むと、片方の障害で全ツールの検知結果を丸ごと失ってしまうため）。tarball 取得・展開の失敗は
    リポジトリ単位の障害として、呼び出し元（`SCAN_ERRORS` を捕捉する側）に伝播させる。
    """
    scanners = default_scanners() if scanners is None else scanners
    tarball_bytes = GitHubRepo.from_full_name(full_name, token).tarball(branch)

    records: list[dict[str, Any]] = []
    with RepoArchive(tarball_bytes) as repo_root:
        for scanner in scanners:
            try:
                records.extend(scanner.scan(full_name, repo_root))
            except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
                logger.warning(
                    "CODESCAN: %s failed for %s, skipping %s results: %s",
                    scanner.name, full_name, scanner.name, exc,
                )
    return records


def _run_codescan_body(db: Session, counters: CrawlCounters) -> None:
    """CODESCAN 本体処理（`run_crawler` へ渡す body 関数）。

    リポジトリ単位で try/except し、1リポジトリの失敗（tarball取得失敗・Semgrepタイムアウト・
    JSON解析失敗等）が CODESCAN 全体を止めないようにする（DEPSCAN のGitHub API呼び出し失敗時と
    同じper-repoパターン）。

    `CrawlCounters` へのマッピングは DEPSCAN の crawler_logs 記録方針を踏襲する:
    inserted=新規検知件数、deleted=今回解決済みにした件数、updated=保持期間超過の実削除件数。
    """
    username = settings.GITHUB_USERNAME
    token = settings.GITHUB_TOKEN
    repos = list_target_repos(username, token)
    logger.info("CODESCAN: %d target repos to scan", len(repos))

    repository = CodeFindingRepository(db)
    all_new_snapshots: list[dict[str, Any]] = []

    for i, repo_info in enumerate(repos, start=1):
        full_name = repo_info["full_name"]
        default_branch = repo_info.get("default_branch") or "main"
        logger.info("CODESCAN: [%d/%d] scanning %s", i, len(repos), full_name)

        try:
            records = scan_repo(full_name, default_branch, token)
        except SCAN_ERRORS as exc:
            logger.warning("CODESCAN: failed to scan %s, skipping: %s", full_name, exc)
            continue

        result = repository.sync(full_name, records)
        counters.inserted += result.inserted
        counters.deleted += result.resolved
        all_new_snapshots.extend(result.new_snapshots)

    # 保持期間超過の削除失敗はクロール全体を失敗させない（DEPSCAN/KEV/OSV/JVNと同様の方針）
    try:
        counters.updated = repository.delete_old_resolved()
    except Exception as exc:
        logger.error("CODESCAN: failed to delete old records: %s", exc, exc_info=True)

    # Issue起票失敗はクロール全体を失敗させない（DEPSCANと同じ方針）
    try:
        file_github_issues(all_new_snapshots)
    except Exception as exc:
        logger.error("CODESCAN: failed to file GitHub issues: %s", exc, exc_info=True)


def fetch_and_scan_code(*, force: bool = False) -> tuple[int, int, int]:
    """CODESCAN のメインエントリポイント。

    GitHub 上の全対象リポジトリのソースコードを Semgrep で静的解析し、自アプリの
    コード自体に潜む脆弱性を検知する。結果は crawler_logs に記録し、新規検知が
    あれば Slack に通知する（`app.core.crawler_runner.run_crawler` 経由）。
    APScheduler から毎日呼び出される。

    Args:
        force: True の場合、今日すでに成功実行済みでも強制的に再実行する（Issue #239）

    Returns:
        (inserted, updated, deleted) のタプル
        （inserted=新規検知件数, updated=保持期間超過の削除件数,
        deleted=今回解決済みにした件数）
    """
    logger.info("=== CODESCAN started ===")
    result = run_crawler("CODESCAN", _run_codescan_body, force=force)
    logger.info(
        "=== CODESCAN completed: inserted=%d, updated=%d, deleted=%d ===", *result,
    )
    return result
