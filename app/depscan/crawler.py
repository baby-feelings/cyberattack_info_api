"""依存ライブラリ脆弱性スキャナー（DEPSCAN）のジョブの組み立て。

GitHub 上の自作アプリ全リポジトリのロックファイルを取得・パースし、OSV API とリアルタイム照合して
脆弱な依存パッケージを検知する。検知結果は DependencyFinding テーブルに保存し、新規分のみ
Slack 通知する。APScheduler から毎日呼び出される。

このモジュールは実行の流れ（`_DepscanJob`。`CrawlJob` の Template Method）の組み立てだけを担う。
役割ごとの実装は次にある。

- `manifests`: ロックファイルの収集とパース
- `finding_builder`: OSV への照合と検知レコードの構築
- `reachability_scan`: 到達可能性（import レベル）の付与
- `repository`: 検知結果の永続化（Upsert・解決済み化・保持期間超過の削除）
"""
import logging
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.crawler_runner import CrawlCounters, CrawlJob
from app.core.notifications.dependency_findings import notify_dependency_findings
from app.depscan.finding_builder import build_findings
from app.depscan.issue_management import close_resolved_repo_issues, file_github_issues
from app.depscan.manifests import collect_dependencies
from app.depscan.reachability_scan import apply_reachability
from app.depscan.repository import DependencyFindingRepository

logger = logging.getLogger(__name__)


class _DepscanJob(CrawlJob):
    """DEPSCAN の1回分の実行（`CrawlJob` のサブクラス）。

    `CrawlCounters` へのマッピング: inserted=新規検知件数、updated=保持期間超過の実削除件数、
    deleted=今回解決済みにした件数。戻り値は (新規検知, 解決済み, スキャンしたリポジトリ数)。
    """

    crawler_type = "DEPSCAN"

    def __init__(self) -> None:
        self.new_snapshots: list[dict[str, Any]] = []
        self.repos_scanned = 0

    def execute(self, db: Session, counters: CrawlCounters) -> None:
        dep_to_repos, self.repos_scanned, repo_visibility = collect_dependencies(
            settings.GITHUB_USERNAME, settings.GITHUB_TOKEN,
        )
        logger.info(
            "DEPSCAN: %d repos scanned, %d unique (ecosystem,package,version) found",
            self.repos_scanned, len(dep_to_repos),
        )

        records = build_findings(dep_to_repos, repo_visibility)

        # 到達可能性の判定失敗はクロール全体を失敗させない（"unknown" のまま据え置く）
        try:
            apply_reachability(records, settings.GITHUB_USERNAME, settings.GITHUB_TOKEN)
        except Exception as exc:
            logger.error("Failed to compute reachability: %s", exc, exc_info=True)

        repository = DependencyFindingRepository(db)
        result = repository.sync(records)
        counters.inserted, self.new_snapshots = result.inserted, result.new_snapshots
        counters.deleted = result.resolved

        # Issue クローズ失敗はクロール全体を失敗させない（Issue起票と同じ方針）
        try:
            close_resolved_repo_issues(db, result.resolved_repos)
        except Exception as exc:
            logger.error("Failed to close resolved GitHub issues: %s", exc, exc_info=True)

        # 保持期間超過の削除失敗はクロール全体を失敗させない（KEV/OSV/JVN と同様の方針）
        try:
            counters.updated = repository.delete_old_resolved()
        except Exception as exc:
            logger.error("Failed to delete old DEPSCAN records: %s", exc, exc_info=True)

    def after_success(self, counters: CrawlCounters) -> None:
        logger.info(
            "=== DEPSCAN completed: new=%d, resolved=%d, purged=%d, repos=%d ===",
            counters.inserted, counters.deleted, counters.updated, self.repos_scanned,
        )
        notify_dependency_findings(self.new_snapshots)
        file_github_issues(self.new_snapshots)

    def result(self, counters: CrawlCounters) -> tuple[int, ...]:
        return counters.inserted, counters.deleted, self.repos_scanned


def fetch_and_scan_dependencies(*, force: bool = False) -> tuple[int, int, int]:
    """DEPSCAN のメインエントリポイント。

    GitHub 上の全対象リポジトリのロックファイルを収集し、OSV API と照合して
    脆弱な依存パッケージを検知する。結果は crawler_logs に記録し、
    新規検知があれば Slack に通知する。APScheduler から毎日呼び出される。

    Args:
        force: True の場合、今日すでに成功実行済みでも強制的に再実行する（Issue #239）

    Returns:
        (new_findings, resolved, repos_scanned) のタプル（スキップ時は (0, 0, 0)）
    """
    logger.info("=== DEPSCAN started ===")
    return _DepscanJob().run(force=force)  # type: ignore[return-value]
