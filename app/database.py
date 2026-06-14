"""データベース接続・セッション管理モジュール。
SQLAlchemy エンジンとセッションファクトリを構築し、
FastAPI の依存性注入（Depends）で使えるジェネレータを提供する。
"""
import logging

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import settings

logger = logging.getLogger(__name__)


def _build_engine():
    """DATABASE_URL に応じてエンジンを構築する。
    SQLite（開発用）と PostgreSQL（本番用）の両方をサポートする。
    """
    url = settings.DATABASE_URL

    if url.startswith("sqlite"):
        # SQLite はマルチスレッド対応のため check_same_thread=False が必要
        engine = create_engine(
            url,
            connect_args={"check_same_thread": False},
            echo=(settings.ENVIRONMENT == "development"),
        )
        # SQLite の外部キー制約を有効化
        @event.listens_for(engine, "connect")
        def enable_sqlite_fk(dbapi_conn, _):
            dbapi_conn.execute("PRAGMA foreign_keys=ON")
    else:
        # PostgreSQL: コネクションプールを設定
        engine = create_engine(
            url,
            pool_pre_ping=True,   # 切断検知のためのヘルスチェック
            pool_size=5,
            max_overflow=10,
            echo=(settings.ENVIRONMENT == "development"),
        )

    logger.info("Database engine created: %s", url.split("@")[-1])
    return engine


engine = _build_engine()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """全モデルの基底クラス。"""
    pass


def get_db():
    """FastAPI の Depends で使用するDBセッションジェネレータ。
    リクエストごとにセッションを作成し、終了後に必ずクローズする。
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
