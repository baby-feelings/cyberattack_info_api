"""クローラー実行ログ API ルーター。

GET /api/crawler-logs  – 実行履歴一覧（種別・件数・所要時間・成否）
"""
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.auth import require_api_key
from app.database import get_db
from app.models import CrawlerLog
from app.schemas import CrawlerLogOut

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/crawler-logs",
    tags=["crawler-logs"],
    dependencies=[Depends(require_api_key)],
)


def _to_out(record: CrawlerLog) -> CrawlerLogOut:
    """CrawlerLog ORM モデルを CrawlerLogOut スキーマに変換する。"""
    return CrawlerLogOut(
        id=record.id,
        crawler_type=record.crawler_type,
        status=record.status,
        started_at=record.started_at.isoformat(),
        finished_at=record.finished_at.isoformat(),
        duration_seconds=record.duration_seconds,
        inserted=record.inserted,
        updated=record.updated,
        deleted=record.deleted,
        error_message=record.error_message,
    )


@router.get(
    "",
    response_model=list[CrawlerLogOut],
    summary="クローラー実行ログ一覧",
    description=(
        "KEV / OSV クローラーの実行履歴を新しい順に返す。"
        "`crawler_type` で絞り込み可能（KEV / OSV）。"
    ),
)
def list_crawler_logs(
    db: Annotated[Session, Depends(get_db)],
    crawler_type: str | None = Query(
        None, description="絞り込み: KEV / OSV（省略時は両方）"
    ),
    limit: int = Query(30, ge=1, le=100, description="取得件数（最大 100）"),
    status: str | None = Query(
        None, description="絞り込み: success / error（省略時は両方）"
    ),
) -> list[CrawlerLogOut]:
    """クローラー実行ログを新しい順に一覧返す。"""
    query = db.query(CrawlerLog)

    # クローラー種別フィルタ（大文字統一）
    if crawler_type:
        query = query.filter(CrawlerLog.crawler_type == crawler_type.upper())

    # 実行結果フィルタ
    if status:
        query = query.filter(CrawlerLog.status == status.lower())

    records = (
        query.order_by(CrawlerLog.started_at.desc())
        .limit(limit)
        .all()
    )

    logger.info(
        "list_crawler_logs: crawler_type=%r status=%r limit=%d → %d records",
        crawler_type, status, limit, len(records),
    )
    return [_to_out(r) for r in records]
