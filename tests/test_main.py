"""app.main（アプリ全体）のテスト。
ヘルスチェック・ルートエンドポイントを検証する。
"""
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient


def test_health_check(client: TestClient):
    """GET /health が 200 を返すことを確認する。"""
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] in ("ok", "degraded")


def test_health_check_db_ok(client: TestClient):
    """GET /health の db_connected フィールドが True であることを確認する。"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["db_connected"] is True


def test_health_check_db_error(client: TestClient):
    """DB 接続失敗時に GET /health が degraded ステータスを返すことを確認する。"""

    # db.execute が例外を送出するジェネレータをモックとして注入
    def failing_get_db():
        mock_db = MagicMock()
        mock_db.execute.side_effect = Exception("DB connection failed")
        yield mock_db

    with patch("app.main.get_db", side_effect=failing_get_db):
        response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["db_connected"] is False


def test_root(client: TestClient):
    """GET / が API 情報を返すことを確認する。"""
    response = client.get("/")
    assert response.status_code == 200
    assert "Cyberattack Info API" in response.json()["name"]
