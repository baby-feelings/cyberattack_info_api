"""GitHub ログイン経由のオンデマンド DEPSCAN スキャンモジュール。

`app.depscan.crawler` の毎日の定期実行（`GITHUB_USERNAME` 専用）とは独立した経路。
DEPSCAN ダッシュボードにログインした任意の GitHub アカウント自身のリポジトリを
その場でスキャンし、進捗を `UserScan` テーブルに記録する。第三者のログインの
たびに Slack 通知・GitHub Issue 起票・crawler_logs への記録が発生しないよう、
それらは一切行わない。
"""
import logging
from datetime import timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.crawler_logs.writer import now_utc
from app.depscan.crawler import (
    FindingKey,
    _build_findings,
    _collect_dependencies,
    _resolve_stale_findings,
    _upsert_findings,
)
from app.depscan.models import UserScan

logger = logging.getLogger(__name__)

# オンデマンドスキャンの再実行間隔。直近のスキャンがこの時間内に完了していれば
# 再スキャンせず、DB に保存済みの結果をそのまま返す（baby-feelings 向けの毎日
# クロールと同様、1日1回程度の頻度で十分という運用方針に合わせる）
RESCAN_INTERVAL_HOURS = 24


def get_user_scan_status(db: Session, username: str) -> UserScan | None:
    """指定ユーザーの直近のオンデマンドスキャン状況を取得する。"""
    return db.query(UserScan).filter(UserScan.username == username).first()


def should_rescan_for_user(db: Session, username: str) -> bool:
    """ログインしたユーザーに対し、オンデマンドスキャンを再実行すべきか判定する。

    - 直近のスキャン記録が無い、またはエラー終了している場合 → 再スキャンする
    - 実行中の場合 → 重複起動を避けるため再スキャンしない
    - 完了済みで `RESCAN_INTERVAL_HOURS` 時間以内なら → 再スキャンしない（DB参照のみ）
    """
    scan = get_user_scan_status(db, username)
    if scan is None or scan.status == "error":
        return True
    if scan.status == "running":
        return False
    # SQLite は DateTime(timezone=True) でもtz情報を保持せず naive で返すため、
    # PostgreSQL（本番）・SQLite（開発/テスト）どちらでも比較できるよう補完する
    started_at = scan.started_at
    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=timezone.utc)
    cutoff = now_utc() - timedelta(hours=RESCAN_INTERVAL_HOURS)
    return started_at < cutoff


def _set_user_scan_status(
    db: Session,
    username: str,
    status: str,
    started_at: Any,
    repos_scanned: int = 0,
    error_message: str | None = None,
) -> None:
    scan = db.query(UserScan).filter(UserScan.username == username).first()
    finished_at = now_utc() if status in ("done", "error") else None
    if scan is None:
        scan = UserScan(
            username=username,
            status=status,
            repos_scanned=repos_scanned,
            started_at=started_at,
            finished_at=finished_at,
            error_message=error_message,
        )
        db.add(scan)
    else:
        scan.status = status
        scan.repos_scanned = repos_scanned
        scan.started_at = started_at
        scan.finished_at = finished_at
        scan.error_message = error_message
    db.commit()


def run_depscan_for_user(username: str, token: str) -> None:
    """GitHub ログインしたユーザー自身のリポジトリをオンデマンドでスキャンする。

    `fetch_and_scan_dependencies`（baby-feelings 向けの毎日の定期実行）とは独立した
    エントリポイント。第三者のログインで Slack/GitHub Issue にノイズを出さないよう、
    通知は一切行わない。進捗は `UserScan` テーブルに記録し、フロントエンドが
    `GET /auth/scan-status` でポーリングできるようにする。
    """
    logger.info("=== DEPSCAN (on-demand for %s) started ===", username)
    started_at = now_utc()
    db: Session = SessionLocal()
    try:
        _set_user_scan_status(db, username, "running", started_at=started_at)

        dep_to_repos, repos_scanned = _collect_dependencies(username, token)
        records = _build_findings(dep_to_repos)
        _upsert_findings(db, records)

        current_keys: set[FindingKey] = {
            (r["repo_full_name"], r["ecosystem"], r["package_name"], r["osv_id"])
            for r in records
        }
        _resolve_stale_findings(db, current_keys, repo_owner_prefix=username)

        _set_user_scan_status(
            db, username, "done", started_at=started_at, repos_scanned=repos_scanned,
        )
        logger.info(
            "=== DEPSCAN (on-demand for %s) completed: repos=%d ===", username, repos_scanned,
        )
    except Exception as exc:
        logger.error("DEPSCAN (on-demand for %s) failed: %s", username, exc, exc_info=True)
        _set_user_scan_status(db, username, "error", started_at=started_at, error_message=str(exc))
    finally:
        db.close()
