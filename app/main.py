"""FastAPI アプリケーション本体。
アプリ起動時にDBテーブルを作成し、APScheduler でクローラーを定期実行する。
"""
import logging
import logging.config
from contextlib import asynccontextmanager

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, Security
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.auth import require_api_key
from app.config import settings
from app.cron import _fetch_cisa_kev, _upsert_vulnerabilities, fetch_and_store_kev
from app.cron_osv import fetch_and_store_osv
from app.database import Base, SessionLocal, engine, get_db
from app.routers import crawler_logs, osv, vulnerabilities
from app.schemas import CrawlResponse, HealthResponse, OsvCrawlResponse

# ──────────────────────────────────────────────
# ロギング設定（標準出力に JSON 風ログを出力）
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# APScheduler（バックグラウンドスケジューラ）
# ──────────────────────────────────────────────
scheduler = BackgroundScheduler()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """アプリの起動・終了時に実行するライフサイクル処理。"""
    # ── 起動処理 ──
    logger.info("Starting Cyberattack Info API (env=%s)", settings.ENVIRONMENT)

    # DB テーブルを自動作成（存在しない場合のみ）
    Base.metadata.create_all(bind=engine)
    # scan_results テーブルを削除（スキャン機能廃止）
    # 失敗してもサービス起動を止めないようベストエフォートで実行する
    try:
        with engine.connect() as conn:
            conn.execute(text("DROP TABLE IF EXISTS scan_results"))
            conn.commit()
        logger.info("scan_results table dropped (scan feature removed)")
    except SQLAlchemyError as exc:
        logger.warning("Could not drop scan_results table: %s", exc)
    logger.info("Database tables created/verified")

    # クローラーを毎日 UTC 19:00（JST 翌日 4:00）に実行
    # CISA KEV クローラー: 毎日 UTC 19:00（JST 翌日 4:00）
    scheduler.add_job(
        fetch_and_store_kev,
        trigger="cron",
        hour=settings.CRON_HOUR_UTC,
        minute=settings.CRON_MINUTE_UTC,
        id="cisa_kev_crawler",
        replace_existing=True,
    )
    # OSV クローラー: 毎日 UTC 20:00（JST 翌日 5:00）
    scheduler.add_job(
        fetch_and_store_osv,
        trigger="cron",
        hour=20,
        minute=0,
        id="osv_crawler",
        replace_existing=True,
    )
    scheduler.start()
    logger.info(
        "Scheduler started: KEV daily UTC %02d:%02d, OSV daily UTC 20:00",
        settings.CRON_HOUR_UTC,
        settings.CRON_MINUTE_UTC,
    )

    yield  # アプリ実行中

    # ── 終了処理 ──
    scheduler.shutdown(wait=False)
    logger.info("Scheduler stopped")


# ──────────────────────────────────────────────
# FastAPI アプリ構築
# ──────────────────────────────────────────────
app = FastAPI(
    title="Cyberattack Info API",
    description=(
        "CISA KEV（Known Exploited Vulnerabilities）カタログを定期収集し、"
        "REST API として配信するプラットフォーム。"
        "Claude Code や CI/CD ツールからの利用に最適化。"
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS 設定（必要に応じてオリジンを制限する）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["X-API-KEY"],
)

# ルーター登録
app.include_router(vulnerabilities.router)
app.include_router(osv.router)
app.include_router(crawler_logs.router)


# ──────────────────────────────────────────────
# ヘルスチェックエンドポイント（認証不要）
# ──────────────────────────────────────────────
@app.get("/health", response_model=HealthResponse, tags=["system"])
def health_check() -> HealthResponse:
    """サービスの稼働状態と DB 接続を確認するエンドポイント。
    ロードバランサーやモニタリングツールからの死活監視に使用する。
    """
    db_ok = False
    db_gen = None
    try:
        db_gen = get_db()
        db = next(db_gen)
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception as exc:
        logger.error("Health check DB error: %s", exc)
    finally:
        # db_gen が生成済みの場合のみクローズ処理を実行（UnboundLocalError 防止）
        if db_gen is not None:
            try:
                next(db_gen)
            except StopIteration:
                pass

    return HealthResponse(
        status="ok" if db_ok else "degraded",
        environment=settings.ENVIRONMENT,
        db_connected=db_ok,
    )


@app.post(
    "/admin/crawl",
    response_model=CrawlResponse,
    tags=["admin"],
    dependencies=[Security(require_api_key)],
    summary="クローラー手動実行",
    description="CISA KEV フィードを即時取得して DB に Upsert する（X-API-KEY 必須）。",
)
def trigger_crawl() -> CrawlResponse:
    """CISA KEV クローラーを手動で即時実行する。
    スケジュール実行を待たずにデータを取得したい場合に使用する。
    """
    logger.info("Manual crawl triggered via /admin/crawl")
    db = SessionLocal()
    try:
        entries = _fetch_cisa_kev()
        inserted, updated = _upsert_vulnerabilities(db, entries)
        logger.info("Manual crawl done: inserted=%d, updated=%d", inserted, updated)
        return CrawlResponse(
            message="Crawl completed successfully",
            inserted=inserted,
            updated=updated,
        )
    except Exception as exc:
        logger.error("Manual crawl failed: %s", exc, exc_info=True)
        raise
    finally:
        db.close()


@app.post(
    "/admin/osv-crawl",
    response_model=OsvCrawlResponse,
    tags=["admin"],
    dependencies=[Security(require_api_key)],
    summary="OSV クローラー手動実行",
    description="OSV GCS から直近データを即時取得して DB に Upsert する（X-API-KEY 必須）。",
)
def trigger_osv_crawl() -> OsvCrawlResponse:
    """OSV クローラーを手動で即時実行する。"""
    logger.info("Manual OSV crawl triggered via /admin/osv-crawl")
    inserted, updated, deleted = fetch_and_store_osv()
    return OsvCrawlResponse(
        message="OSV crawl completed",
        inserted=inserted,
        updated=updated,
        deleted=deleted,
    )


@app.get("/", tags=["system"])
def root():
    """ルートエンドポイント（API 情報を返す）。"""
    return {
        "name": "Cyberattack Info API",
        "version": "1.0.0",
        "docs": "/docs",
        "redoc": "/redoc",
        "health": "/health",
    }
