"""クローラー実行ログ書き込みユーティリティ。

KEV / OSV 両クローラーから呼ばれる共通ヘルパー。
メインのクロール処理とは独立したセッションを使い、
クロールがエラー終了した場合でもログが確実にコミットされるようにする。
"""
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import CrawlerLog

logger = logging.getLogger(__name__)


def write_crawler_log(
    crawler_type: str,
    status: str,
    started_at: datetime,
    finished_at: datetime,
    inserted: int = 0,
    updated: int = 0,
    deleted: int = 0,
    error_message: str | None = None,
) -> None:
    """クローラー実行結果を crawler_logs テーブルに記録する。

    メイン処理のセッションとは別セッションを使うため、
    クロール失敗時でもログは確実にコミットされる。

    Args:
        crawler_type:  "KEV" または "OSV"
        status:        "success" または "error"
        started_at:    クローラー開始日時（UTC）
        finished_at:   クローラー終了日時（UTC）
        inserted:      新規挿入件数
        updated:       更新件数
        deleted:       削除件数（OSV のみ）
        error_message: エラー時のメッセージ
    """
    duration = (finished_at - started_at).total_seconds()
    log_db: Session = SessionLocal()
    try:
        log = CrawlerLog(
            crawler_type=crawler_type,
            status=status,
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=duration,
            inserted=inserted,
            updated=updated,
            deleted=deleted,
            error_message=error_message,
        )
        log_db.add(log)
        log_db.commit()
        logger.info(
            "CrawlerLog saved: type=%s status=%s inserted=%d updated=%d deleted=%d "
            "duration=%.1fs",
            crawler_type, status, inserted, updated, deleted, duration,
        )
    except Exception as exc:
        # ログ書き込み失敗はアプリを止めない
        logger.error("Failed to write crawler log: %s", exc)
    finally:
        log_db.close()


def now_utc() -> datetime:
    """現在の UTC 日時を返す（クローラー開始・終了時刻の記録用）。"""
    return datetime.now(timezone.utc)
