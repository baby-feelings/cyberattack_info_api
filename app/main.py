"""FastAPI アプリケーション本体。
アプリ起動時にDBテーブルを作成し、APScheduler でクローラーを定期実行する。

/admin/* の手動トリガーエンドポイントは各ドメインの router.py（admin_router）に定義する。
本ファイルは include_router 呼び出しと lifespan・スケジューラ配線に専念する。
"""
import logging
import logging.config
from contextlib import asynccontextmanager

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.auth.router import router as auth_router
from app.core.config import settings
from app.core.database import Base, engine, get_db
from app.core.metrics import router as metrics_router
from app.core.schemas import HealthResponse
from app.crawler_logs.router import router as crawler_logs_router
from app.depscan.crawler import fetch_and_scan_dependencies
from app.depscan.router import admin_router as depscan_admin_router
from app.depscan.router import router as depscan_router
from app.depsops.router import admin_router as depsops_admin_router
from app.depsops.router import router as depsops_router
from app.depsops.runner import run_dependabot_ops
from app.jvn.crawler import fetch_and_store_jvn
from app.jvn.router import admin_router as jvn_admin_router
from app.jvn.router import router as jvn_router
from app.kev.crawler import fetch_and_store_kev
from app.kev.router import admin_router as kev_admin_router
from app.kev.router import router as kev_router
from app.kev.taxii import taxii_router
from app.osv.crawler import fetch_and_store_osv
from app.osv.router import admin_router as osv_admin_router
from app.osv.router import router as osv_router

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
    # OSV クローラー
    scheduler.add_job(
        fetch_and_store_osv,
        trigger="cron",
        hour=settings.OSV_CRON_HOUR_UTC,
        minute=0,
        id="osv_crawler",
        replace_existing=True,
    )
    # JVN クローラー
    scheduler.add_job(
        fetch_and_store_jvn,
        trigger="cron",
        hour=settings.JVN_CRON_HOUR_UTC,
        minute=0,
        id="jvn_crawler",
        replace_existing=True,
    )
    # 依存ライブラリ脆弱性スキャナー（DEPSCAN）
    scheduler.add_job(
        fetch_and_scan_dependencies,
        trigger="cron",
        hour=settings.DEPSCAN_CRON_HOUR_UTC,
        minute=0,
        id="depscan_crawler",
        replace_existing=True,
    )
    # Dependabot PR 自動運用（DEPSOPS）
    scheduler.add_job(
        run_dependabot_ops,
        trigger="cron",
        hour=settings.DEPSOPS_CRON_HOUR_UTC,
        minute=0,
        id="dependabot_ops",
        replace_existing=True,
    )
    scheduler.start()
    logger.info(
        "Scheduler started: KEV UTC %02d:%02d / OSV UTC %02d:00 / JVN UTC %02d:00 / "
        "DEPSCAN UTC %02d:00 / DEPSOPS UTC %02d:00",
        settings.CRON_HOUR_UTC, settings.CRON_MINUTE_UTC,
        settings.OSV_CRON_HOUR_UTC, settings.JVN_CRON_HOUR_UTC,
        settings.DEPSCAN_CRON_HOUR_UTC, settings.DEPSOPS_CRON_HOUR_UTC,
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
    docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
)

# CORS 設定（本番はダッシュボードドメインのみ許可、開発時は localhost も許可）
_cors_origins = (
    ["https://cyberattackinfoapi.vercel.app", "http://localhost:5173", "http://localhost:3000"]
    if settings.ENVIRONMENT != "production"
    else ["https://cyberattackinfoapi.vercel.app"]
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["X-API-KEY", "Authorization"],
)

# ルーター登録
app.include_router(auth_router)
app.include_router(kev_router)
app.include_router(osv_router)
app.include_router(jvn_router)
app.include_router(crawler_logs_router)
app.include_router(depscan_router)
app.include_router(depsops_router)
app.include_router(kev_admin_router)
app.include_router(osv_admin_router)
app.include_router(jvn_admin_router)
app.include_router(depscan_admin_router)
app.include_router(depsops_admin_router)
app.include_router(metrics_router)
app.include_router(taxii_router)


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
        "docs": "/docs",
        "redoc": "/redoc",
        "health": "/health",
    }
