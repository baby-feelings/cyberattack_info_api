"""クローラー実行の共通オーケストレーション（Template Method）。

KEV / OSV / JVN の各 fetch_and_store_* が個別に実装していた
「started_at 計測 → DB セッション生成 → 本体処理 → crawler_logs 記録 →
Slack 通知 → DB セッションクローズ」という定型処理を一元化する。

本体処理（クローラー種別ごとに異なる取得・Upsert ロジック）は body 関数として
呼び出し側から渡し、進捗件数は CrawlCounters に加算していく。エラー発生時も
その時点までの counters の値を crawler_logs に反映する（例: OSV クローラーは
複数エコシステムを順に処理するため、途中のエコシステムで例外が発生しても
それまでに成功した件数を記録する）。
"""
import logging
from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.core.notifications import notify_error, notify_success
from app.core.types import CrawlerType
from app.crawler_logs.writer import now_utc, write_crawler_log

logger = logging.getLogger(__name__)


@dataclass
class CrawlCounters:
    """クロール処理の進捗件数。本体処理が処理の進行に応じて加算する。"""

    inserted: int = 0
    updated: int = 0
    deleted: int = 0

    def as_tuple(self) -> tuple[int, int, int]:
        return self.inserted, self.updated, self.deleted


def run_crawler(
    crawler_type: CrawlerType,
    body: Callable[[Session, CrawlCounters], None],
) -> tuple[int, int, int]:
    """クローラーの共通実行ラッパー。

    Args:
        crawler_type: "KEV" / "OSV" / "JVN"
        body: (db, counters) を受け取り、counters を更新しながら本体処理を行う関数

    Returns:
        (inserted, updated, deleted) のタプル

    Raises:
        body 内で処理されず伝播した例外（crawler_logs への記録・Slack通知の後、再送出する）
    """
    started_at = now_utc()
    counters = CrawlCounters()
    db: Session = SessionLocal()
    try:
        body(db, counters)
        logger.info(
            "%s crawler completed: inserted=%d, updated=%d, deleted=%d",
            crawler_type, counters.inserted, counters.updated, counters.deleted,
        )
        write_crawler_log(
            crawler_type=crawler_type,
            status="success",
            started_at=started_at,
            finished_at=now_utc(),
            inserted=counters.inserted,
            updated=counters.updated,
            deleted=counters.deleted,
        )
        notify_success(crawler_type, counters.inserted, counters.updated, counters.deleted)
        return counters.as_tuple()
    except Exception as exc:
        logger.error("%s crawler failed: %s", crawler_type, exc, exc_info=True)
        write_crawler_log(
            crawler_type=crawler_type,
            status="error",
            started_at=started_at,
            finished_at=now_utc(),
            inserted=counters.inserted,
            updated=counters.updated,
            deleted=counters.deleted,
            error_message=str(exc),
        )
        notify_error(crawler_type, str(exc))
        raise
    finally:
        db.close()
