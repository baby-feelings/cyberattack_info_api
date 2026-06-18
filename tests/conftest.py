"""pytest 共通フィクスチャ。
テスト用にファイルベース SQLite DB と FastAPI テストクライアントを提供する。
各テスト間のデータ汚染を防ぐため、テスト毎にテーブルを truncate する。
"""
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# テスト用環境変数を設定（app モジュールのインポート前に行う必要がある）
os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402

# ── テスト用 SQLite DB ─────────────────────────────────────────
TEST_DATABASE_URL = "sqlite:///./test.db"
test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
)
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """テストセッション開始時にテーブルを作成し、終了時に削除する。"""
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    # エンジンの接続を全て閉じてからファイルを削除（Windows のファイルロック対策）
    test_engine.dispose()
    try:
        if os.path.exists("test.db"):
            os.remove("test.db")
    except OSError:
        pass  # ファイルロックが残っている場合は無視（CI の Linux 環境では発生しない）


@pytest.fixture(autouse=True)
def clean_db():
    """各テスト実行前にテーブルのデータをクリアし、テスト間のデータ汚染を防ぐ。"""
    yield
    # テスト終了後にテーブルを truncate（SQLite では DELETE を使用）
    with test_engine.connect() as conn:
        conn.execute(text("DELETE FROM crawler_logs"))
        conn.execute(text("DELETE FROM jvn_vulnerabilities"))
        conn.execute(text("DELETE FROM osv_vulnerabilities"))
        conn.execute(text("DELETE FROM vulnerabilities"))
        conn.commit()


@pytest.fixture
def db_session():
    """各テスト用の DB セッション。"""
    session = TestSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db_session):
    """FastAPI テストクライアント。
    本番 DB の代わりにテスト用 DB セッションを注入する。
    """
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    app.dependency_overrides.clear()


# テスト用 API キー
TEST_API_KEY = "test-api-key-for-pytest"
