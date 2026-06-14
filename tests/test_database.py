"""database.py のユニットテスト。
SQLite / PostgreSQL エンジン生成パスを検証する。
"""
import os

# app モジュールのインポート前に環境変数を設定
os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from unittest.mock import MagicMock, call, patch  # noqa: E402

from app.database import _build_engine  # noqa: E402


def test_build_engine_sqlite_path():
    """DATABASE_URL が sqlite の場合、check_same_thread=False で engine が作られることを確認する。"""
    mock_engine = MagicMock()

    with patch("app.database.settings") as mock_settings, \
         patch("app.database.create_engine", return_value=mock_engine) as mock_ce, \
         patch("app.database.event") as mock_event:
        mock_settings.DATABASE_URL = "sqlite:///./test_build.db"
        mock_settings.ENVIRONMENT = "development"

        result = _build_engine()

    mock_ce.assert_called_once_with(
        "sqlite:///./test_build.db",
        connect_args={"check_same_thread": False},
        echo=True,
    )
    # event.listens_for が "connect" イベントに対して呼ばれていることを確認
    mock_event.listens_for.assert_called_once_with(mock_engine, "connect")
    assert result is mock_engine


def test_build_engine_postgresql_path():
    """DATABASE_URL が PostgreSQL の場合、pool_pre_ping=True で engine が作られることを確認する。"""
    mock_engine = MagicMock()

    with patch("app.database.settings") as mock_settings, \
         patch("app.database.create_engine", return_value=mock_engine) as mock_ce:
        mock_settings.DATABASE_URL = "postgresql://user:pass@localhost/testdb"
        mock_settings.ENVIRONMENT = "production"

        result = _build_engine()

    mock_ce.assert_called_once_with(
        "postgresql://user:pass@localhost/testdb",
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        echo=False,
    )
    assert result is mock_engine
