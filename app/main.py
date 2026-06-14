"""FastAPI アプリケーション本体。
アプリ起動時にDBテーブルを作成し、APScheduler でクローラーを定期実行する。
"""
import logging
import logging.config
from contextlib import asynccontextmanager

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.config import settings
from app.cron import fetch_and_store_kev
from app.database import Base, engine, get_db
from app.routers import vulnerabilities
from app.schemas import HealthResponse

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
    logger.info("Database tables created/verified")

    # クローラーを毎日 UTC 19:00（JST 翌日 4:00）に実行
    scheduler.add_job(
        fetch_and_store_kev,
        trigger="cron",
        hour=settings.CRON_HOUR_UTC,
        minute=settings.CRON_MINUTE_UTC,
        id="cisa_kev_crawler",
        replace_existing=True,
    )
    scheduler.start()
    logger.info(
        "Scheduler started: CISA KEV crawler at UTC %02d:%02d daily",
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
    # 本番環境では Swagger UI を無効化してセキュリティを高める
    docs_url="/docs" if settings.ENVIRONMENT == "development" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT == "development" else None,
)

# CORS 設定（必要に応じてオリジンを制限する）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["X-API-KEY"],
)

# ルーター登録
app.include_router(vulnerabilities.router)


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


@app.get("/", tags=["system"])
def root():
    """ルートエンドポイント（API 情報を返す）。"""
    return {
        "name": "Cyberattack Info API",
        "version": "1.0.0",
        "docs": "/docs" if settings.ENVIRONMENT == "development" else "disabled",
        "health": "/health",
    }
