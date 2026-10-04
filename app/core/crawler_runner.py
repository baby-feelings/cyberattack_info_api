"""クローラー実行の共通オーケストレーション（Template Method）。

KEV / OSV / JVN / DEPSCAN / CODESCAN / DEPSOPS の各エントリポイントが個別に実装していた
「重複実行スキップ → started_at 計測 → DB セッション生成 → 本体処理 → crawler_logs 記録 →
Slack 通知 → DB セッションクローズ」という定型処理を `CrawlJob` に一元化する。

- 単純な関数だけで済むクローラー（KEV/OSV/JVN/CODESCAN）は `run_crawler(type, body)` を使う。
- 固有の状態・通知・戻り値を持つスキャナー（DEPSCAN/DEPSOPS）は `CrawlJob` のサブクラスにし、
  `execute`（本体）・`after_success`（成功後の通知）・`result`（戻り値）だけを差し替える。

本体処理（クローラー種別ごとに異なる取得・Upsert ロジック）は body 関数として
呼び出し側から渡し、進捗件数は CrawlCounters に加算していく。エラー発生時も
その時点までの counters の値を crawler_logs に反映する（例: OSV クローラーは
複数エコシステムを順に処理するため、途中のエコシステムで例外が発生しても
それまでに成功した件数を記録する）。
"""
import logging
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, time, timezone

from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.core.notifications import notify_error, notify_success
from app.core.types import CrawlerType
from app.crawler_logs.models import CrawlerLog
from app.crawler_logs.writer import now_utc, write_crawler_log

logger = logging.getLogger(__name__)


def already_succeeded_today(crawler_type: CrawlerType) -> bool:
    """指定クローラー種別が、今日（UTC日付）既に成功実行済みかを確認する（Issue #239）。

    本アプリはクローラーの起動経路を2つ持つ: (1) アプリ内部の APScheduler（各
    settings.*_CRON_HOUR_UTC で毎日発火）、(2) GitHub Actions の daily-crawl.yml
    （「APSchedulerがネットワーク障害等で不発火だった場合のバックアップ」として
    無条件に毎日発火）。OCI移行後はAPSchedulerが確実に動作するため、実質的に
    バックアップではなく常に二重実行になっていた。KEV/OSV/JVN/DEPSCAN/CODESCANは
    自然キーのUpsertのため二重実行の実害は小さいが、DEPSOPSは実行ごとに1行追記する
    ログ設計のため件数が二重に膨れ上がっていた（本番で2388件中約半数が重複）。

    どちらが先に発火しても「その日2回目の実行」を検知してスキップできるよう、
    実行順ではなく「今日すでに成功記録があるか」で判定する。
    """
    db = SessionLocal()
    try:
        today_start_utc = datetime.combine(now_utc().date(), time.min, tzinfo=timezone.utc)
        existing = (
            db.query(CrawlerLog)
            .filter(
                CrawlerLog.crawler_type == crawler_type,
                CrawlerLog.status == "success",
                CrawlerLog.started_at >= today_start_utc,
            )
            .first()
        )
        return existing is not None
    finally:
        db.close()


@dataclass
class CrawlCounters:
    """クロール処理の進捗件数。本体処理が処理の進行に応じて加算する。"""

    inserted: int = 0
    updated: int = 0
    deleted: int = 0

    def as_tuple(self) -> tuple[int, int, int]:
        return self.inserted, self.updated, self.deleted


class CrawlJob(ABC):
    """クローラー1回分の実行ライフサイクル（Template Method）。

    `run` が共通の流れ（重複実行スキップ・時刻計測・DBセッション管理・crawler_logs記録・
    エラー通知）を担い、サブクラスは次の3点だけを差し替える。

    - `execute`: 本体処理。進捗件数を `counters` に加算する（エラー時もその時点の値をログへ残す）
    - `after_success`: 成功後の通知など（DBセッションを閉じた後・例外を握りつぶさずに呼ぶ）
    - `result`: 呼び出し側へ返す値（既定は counters のタプル）
    """

    crawler_type: CrawlerType

    @abstractmethod
    def execute(self, db: Session, counters: CrawlCounters) -> None:
        """本体処理。例外はそのまま伝播させる（`run` がログ・通知した後に再送出する）。"""

    def after_success(self, counters: CrawlCounters) -> None:
        """成功後の通知。既定は KEV/OSV/JVN 共通の Slack 成功通知。"""
        notify_success(self.crawler_type, counters.inserted, counters.updated, counters.deleted)

    def result(self, counters: CrawlCounters) -> tuple[int, ...]:
        """呼び出し側へ返す値。既定は (inserted, updated, deleted)。"""
        return counters.as_tuple()

    def skipped_result(self) -> tuple[int, ...]:
        """今日すでに成功実行済みでスキップした場合に返す値。"""
        return 0, 0, 0

    def run(self, *, force: bool = False) -> tuple[int, ...]:
        """共通の実行フロー。

        Args:
            force: True の場合、今日すでに成功実行済みでも強制的に再実行する
                （動作確認等の明示的な手動再実行用。APScheduler・GitHub Actions の
                自動トリガーは常に False で呼ぶ、Issue #239）

        Raises:
            execute 内で処理されず伝播した例外（crawler_logs への記録・Slack通知の後、再送出する）
        """
        crawler_type = self.crawler_type
        if not force and already_succeeded_today(crawler_type):
            logger.info(
                "%s crawler already succeeded today (UTC), skipping duplicate run", crawler_type,
            )
            return self.skipped_result()

        started_at = now_utc()
        counters = CrawlCounters()
        db: Session = SessionLocal()
        try:
            self.execute(db, counters)
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

        # 成功後の通知はDBセッションを閉じた後に行う（通知側の例外をクロール失敗扱いにしない）
        self.after_success(counters)
        return self.result(counters)


class _CallableCrawlJob(CrawlJob):
    """`body` 関数だけで表現できるクローラー用の最小サブクラス（`run_crawler` が使う）。"""

    def __init__(
        self, crawler_type: CrawlerType, body: Callable[[Session, CrawlCounters], None],
    ) -> None:
        self.crawler_type = crawler_type
        self._body = body

    def execute(self, db: Session, counters: CrawlCounters) -> None:
        self._body(db, counters)


def run_crawler(
    crawler_type: CrawlerType,
    body: Callable[[Session, CrawlCounters], None],
    *,
    force: bool = False,
) -> tuple[int, int, int]:
    """クローラーの共通実行ラッパー（関数だけで済むクローラー向け）。

    Args:
        crawler_type: "KEV" / "OSV" / "JVN" / "CODESCAN"
        body: (db, counters) を受け取り、counters を更新しながら本体処理を行う関数
        force: True の場合、今日すでに成功実行済みでも強制的に再実行する

    Returns:
        (inserted, updated, deleted) のタプル（スキップ時は (0, 0, 0)）

    Raises:
        body 内で処理されず伝播した例外（crawler_logs への記録・Slack通知の後、再送出する）
    """
    return _CallableCrawlJob(crawler_type, body).run(force=force)  # type: ignore[return-value]
