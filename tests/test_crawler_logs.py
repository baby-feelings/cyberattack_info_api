"""クローラー実行ログ API のテスト。

GET /api/crawler-logs エンドポイントおよび write_crawler_log ヘルパーを検証する。
"""
from datetime import datetime, timezone
from unittest.mock import patch

from app.crawler_log import write_crawler_log
from app.models import CrawlerLog
from tests.conftest import TEST_API_KEY

HEADERS = {"X-API-KEY": TEST_API_KEY}

# テスト用の固定日時
_T0 = datetime(2026, 6, 15, 19, 0, 0, tzinfo=timezone.utc)
_T1 = datetime(2026, 6, 15, 19, 1, 30, tzinfo=timezone.utc)  # 90 秒後


def _make_log(db_session, **kwargs) -> CrawlerLog:
    """テスト用 CrawlerLog レコードを挿入するヘルパー。"""
    defaults = {
        "crawler_type": "KEV",
        "status": "success",
        "started_at": _T0,
        "finished_at": _T1,
        "duration_seconds": 90.0,
        "inserted": 5,
        "updated": 2,
        "deleted": 0,
        "error_message": None,
    }
    defaults.update(kwargs)
    record = CrawlerLog(**defaults)
    db_session.add(record)
    db_session.commit()
    return record


# ──────────────────────────────────────────────────────────────
# GET /api/crawler-logs
# ──────────────────────────────────────────────────────────────


class TestListCrawlerLogs:
    def test_empty(self, client):
        """ログがない場合は空リストを返す。"""
        res = client.get("/api/crawler-logs", headers=HEADERS)
        assert res.status_code == 200
        assert res.json() == []

    def test_requires_auth(self, client):
        """API キーなしは 403。"""
        res = client.get("/api/crawler-logs")
        assert res.status_code == 403

    def test_returns_log_fields(self, client, db_session):
        """全フィールドが正しく返ること。"""
        _make_log(db_session, inserted=10, updated=3)
        res = client.get("/api/crawler-logs", headers=HEADERS)
        assert res.status_code == 200
        body = res.json()
        assert len(body) == 1
        log = body[0]
        assert log["crawler_type"] == "KEV"
        assert log["status"] == "success"
        assert log["inserted"] == 10
        assert log["updated"] == 3
        assert log["deleted"] == 0
        assert log["duration_seconds"] == 90.0
        assert log["error_message"] is None
        # ISO 8601 形式であること
        assert "2026-06-15" in log["started_at"]

    def test_sorted_by_started_at_desc(self, client, db_session):
        """新しい順に返ること。"""
        early = datetime(2026, 6, 14, 19, 0, 0, tzinfo=timezone.utc)
        late  = datetime(2026, 6, 15, 19, 0, 0, tzinfo=timezone.utc)
        _make_log(db_session, started_at=early, finished_at=early)
        _make_log(db_session, started_at=late,  finished_at=late)
        res = client.get("/api/crawler-logs", headers=HEADERS)
        body = res.json()
        assert body[0]["started_at"] > body[1]["started_at"]

    def test_filter_by_crawler_type_kev(self, client, db_session):
        """crawler_type=KEV で KEV ログのみ返ること。"""
        _make_log(db_session, crawler_type="KEV")
        _make_log(db_session, crawler_type="OSV")
        res = client.get("/api/crawler-logs?crawler_type=KEV", headers=HEADERS)
        body = res.json()
        assert len(body) == 1
        assert body[0]["crawler_type"] == "KEV"

    def test_filter_by_crawler_type_osv(self, client, db_session):
        """crawler_type=OSV で OSV ログのみ返ること。"""
        _make_log(db_session, crawler_type="KEV")
        _make_log(db_session, crawler_type="OSV", deleted=10)
        res = client.get("/api/crawler-logs?crawler_type=OSV", headers=HEADERS)
        body = res.json()
        assert len(body) == 1
        assert body[0]["crawler_type"] == "OSV"
        assert body[0]["deleted"] == 10

    def test_filter_by_crawler_type_case_insensitive(self, client, db_session):
        """crawler_type フィルタは大文字に正規化されること。"""
        _make_log(db_session, crawler_type="KEV")
        res = client.get("/api/crawler-logs?crawler_type=kev", headers=HEADERS)
        assert len(res.json()) == 1

    def test_filter_by_status_success(self, client, db_session):
        """status=success でフィルタできること。"""
        _make_log(db_session, status="success")
        _make_log(db_session, status="error", error_message="timeout")
        res = client.get("/api/crawler-logs?status=success", headers=HEADERS)
        body = res.json()
        assert len(body) == 1
        assert body[0]["status"] == "success"

    def test_filter_by_status_error(self, client, db_session):
        """status=error でエラーログのみ返り、error_message が含まれること。"""
        _make_log(db_session, status="success")
        _make_log(db_session, status="error", error_message="Connection refused")
        res = client.get("/api/crawler-logs?status=error", headers=HEADERS)
        body = res.json()
        assert len(body) == 1
        assert body[0]["status"] == "error"
        assert body[0]["error_message"] == "Connection refused"

    def test_limit_parameter(self, client, db_session):
        """limit パラメータが機能すること。"""
        for i in range(5):
            t = datetime(2026, 6, i + 10, 0, 0, 0, tzinfo=timezone.utc)
            _make_log(db_session, started_at=t, finished_at=t)
        res = client.get("/api/crawler-logs?limit=3", headers=HEADERS)
        assert len(res.json()) == 3

    def test_error_log_has_message(self, client, db_session):
        """エラーログに error_message が記録されていること。"""
        _make_log(
            db_session,
            status="error",
            inserted=0,
            updated=0,
            error_message="HTTP 503 Service Unavailable",
        )
        res = client.get("/api/crawler-logs", headers=HEADERS)
        log = res.json()[0]
        assert log["status"] == "error"
        assert "503" in log["error_message"]


# ──────────────────────────────────────────────────────────────
# write_crawler_log ヘルパー
# ──────────────────────────────────────────────────────────────


class TestWriteCrawlerLog:
    def test_writes_success_log(self, db_session):
        """成功ログが DB に書き込まれること。"""
        # write_crawler_log は内部で SessionLocal を使うため、テスト DB を注入
        from tests.conftest import TestSessionLocal
        with patch("app.crawler_log.SessionLocal", TestSessionLocal):
            write_crawler_log(
                crawler_type="KEV",
                status="success",
                started_at=_T0,
                finished_at=_T1,
                inserted=3,
                updated=1,
            )

        record = db_session.query(CrawlerLog).first()
        assert record is not None
        assert record.crawler_type == "KEV"
        assert record.status == "success"
        assert record.inserted == 3
        assert record.updated == 1
        assert record.deleted == 0
        assert record.error_message is None
        assert record.duration_seconds == 90.0

    def test_writes_error_log(self, db_session):
        """エラーログが DB に書き込まれること。"""
        from tests.conftest import TestSessionLocal
        with patch("app.crawler_log.SessionLocal", TestSessionLocal):
            write_crawler_log(
                crawler_type="OSV",
                status="error",
                started_at=_T0,
                finished_at=_T1,
                error_message="Connection timeout",
            )

        record = db_session.query(CrawlerLog).first()
        assert record is not None
        assert record.crawler_type == "OSV"
        assert record.status == "error"
        assert record.error_message == "Connection timeout"
        assert record.inserted == 0

    def test_write_failure_does_not_raise(self):
        """DB 書き込み失敗時も例外を外に伝播させないこと。"""
        from unittest.mock import MagicMock
        mock_session = MagicMock()
        mock_session.return_value.add.side_effect = Exception("DB error")

        with patch("app.crawler_log.SessionLocal", mock_session):
            # 例外が発生しないことを確認
            write_crawler_log(
                crawler_type="KEV",
                status="success",
                started_at=_T0,
                finished_at=_T1,
            )

    def test_osv_log_includes_deleted(self, db_session):
        """OSV ログに deleted 件数が記録されること。"""
        from tests.conftest import TestSessionLocal
        with patch("app.crawler_log.SessionLocal", TestSessionLocal):
            write_crawler_log(
                crawler_type="OSV",
                status="success",
                started_at=_T0,
                finished_at=_T1,
                inserted=100,
                updated=50,
                deleted=30,
            )

        record = db_session.query(CrawlerLog).first()
        assert record.deleted == 30
        assert record.inserted == 100
        assert record.updated == 50


# ──────────────────────────────────────────────────────────────
# KEV クローラーとの統合（write_crawler_log 呼び出しを確認）
# ──────────────────────────────────────────────────────────────


class TestCrawlerLogIntegration:
    def test_kev_crawler_logs_on_success(self):
        """KEV クローラー成功時に write_crawler_log が呼ばれること。"""
        from unittest.mock import patch
        mock_entries = [{"cveID": "CVE-2024-0001", "vendorProject": "Test",
                         "product": "Product", "vulnerabilityName": "Vuln",
                         "shortDescription": "desc", "dateAdded": "2024-01-01"}]

        with patch("app.cron._fetch_cisa_kev", return_value=mock_entries), \
             patch("app.cron._upsert_vulnerabilities", return_value=(1, 0)), \
             patch("app.cron.notify_new_vulnerabilities"), \
             patch("app.cron.write_crawler_log") as mock_log, \
             patch("app.cron.SessionLocal"):
            from app.cron import fetch_and_store_kev
            fetch_and_store_kev()

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["crawler_type"] == "KEV"
        assert call_kwargs["status"] == "success"
        assert call_kwargs["inserted"] == 1

    def test_kev_crawler_logs_on_error(self):
        """KEV クローラーエラー時に status=error で write_crawler_log が呼ばれること。"""
        from unittest.mock import patch

        import httpx

        with patch("app.cron._fetch_cisa_kev", side_effect=httpx.ConnectError("timeout")), \
             patch("app.cron.notify_crawl_error"), \
             patch("app.cron.write_crawler_log") as mock_log, \
             patch("app.cron.SessionLocal"):
            from app.cron import fetch_and_store_kev
            try:
                fetch_and_store_kev()
            except Exception:
                pass

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["crawler_type"] == "KEV"
        assert call_kwargs["status"] == "error"
        assert call_kwargs["error_message"] is not None

    def test_osv_crawler_logs_on_success(self):
        """OSV クローラー成功時に write_crawler_log が呼ばれること。"""
        from unittest.mock import patch

        with patch("app.cron_osv._query_packages_batch", return_value=[]), \
             patch("app.cron_osv._delete_old_osv_records", return_value=5), \
             patch("app.cron_osv.notify_osv_new_vulnerabilities"), \
             patch("app.cron_osv.write_crawler_log") as mock_log, \
             patch("app.cron_osv.SessionLocal"):
            from app.cron_osv import fetch_and_store_osv
            fetch_and_store_osv()

        mock_log.assert_called_once()
        call_kwargs = mock_log.call_args[1]
        assert call_kwargs["crawler_type"] == "OSV"
        assert call_kwargs["status"] == "success"
        assert call_kwargs["deleted"] == 5
