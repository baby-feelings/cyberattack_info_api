"""OSV の API（一覧・統計・個別取得・手動実行）と、スキーマ・月別集計の式のテスト。
"""
import os
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")


from app.osv.models import OsvVulnerability  # noqa: E402

TEST_API_KEY = "test-api-key-for-pytest"
HEADERS = {"X-API-KEY": TEST_API_KEY}

# テスト用の OSV エントリを生成するヘルパー（days フィルタの範囲内に収まるよう実行時刻基準にする）
_NOW = datetime.now(UTC)


def _make_osv(db_session, **kwargs):
    """テスト用 OsvVulnerability レコードを DB に挿入する。"""
    defaults = {
        "osv_id": "GHSA-test-0001",
        "ecosystem": "PyPI",
        "package_name": "fastapi",
        "aliases": ["CVE-2024-00001"],
        "summary": "Test vulnerability",
        "details": None,
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected_versions": ["0.1.0"],
        "fixed_versions": ["0.2.0"],
        "references": ["https://example.com/advisory"],
        "published": _NOW,
        "modified": _NOW,
    }
    defaults.update(kwargs)
    record = OsvVulnerability(**defaults)
    db_session.add(record)
    db_session.commit()
    return record


def _make_vuln(
    osv_id: str = "GHSA-test-0001",
    modified: str = "2026-06-01T00:00:00Z",
    ecosystem: str = "PyPI",
    pkg_name: str = "testpkg",
) -> dict:
    """OSV API が返す脆弱性オブジェクトのモックを生成する。"""
    return {
        "id": osv_id,
        "modified": modified,
        "published": "2026-01-01T00:00:00Z",
        "aliases": ["CVE-2026-00001"],
        "summary": f"Vuln {osv_id}",
        "details": "Detailed description",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"name": pkg_name, "ecosystem": ecosystem},
                "versions": ["1.0.0"],
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"fixed": "1.1.0"}]}
                ],
            }
        ],
        "references": [{"url": "https://example.com/advisory"}],
    }


# ──────────────────────────────────────────────────────────────
# GET /api/osv (一覧)
# ──────────────────────────────────────────────────────────────


class TestListOsv:
    def test_empty(self, client):
        """データがない場合は total=0 の空リストを返す。"""
        res = client.get("/api/osv", headers=HEADERS)
        assert res.status_code == 200
        body = res.json()
        assert body["total"] == 0
        assert body["data"] == []

    def test_requires_auth(self, client):
        """API キーなしは 403。"""
        res = client.get("/api/osv")
        assert res.status_code == 403

    def test_returns_record(self, client, db_session):
        """登録済みの OSV レコードが返ること。"""
        _make_osv(db_session)
        res = client.get("/api/osv", headers=HEADERS)
        assert res.status_code == 200
        body = res.json()
        assert body["total"] == 1
        item = body["data"][0]
        assert item["osv_id"] == "GHSA-test-0001"
        assert item["ecosystem"] == "PyPI"
        assert item["package_name"] == "fastapi"
        assert item["severity"] == "HIGH"
        assert item["cvss_score"] == 7.5
        assert item["aliases"] == ["CVE-2024-00001"]

    def test_filter_ecosystem(self, client, db_session):
        """ecosystem フィルタが機能すること。"""
        _make_osv(db_session, osv_id="GHSA-py-001", ecosystem="PyPI", package_name="pkg-a")
        _make_osv(db_session, osv_id="GHSA-npm-001", ecosystem="npm", package_name="pkg-b")
        res = client.get("/api/osv?ecosystem=npm", headers=HEADERS)
        body = res.json()
        assert body["total"] == 1
        assert body["data"][0]["ecosystem"] == "npm"

    def test_filter_severity(self, client, db_session):
        """severity フィルタが機能すること。"""
        _make_osv(db_session, osv_id="GHSA-crit-001", severity="CRITICAL")
        _make_osv(db_session, osv_id="GHSA-low-001", severity="LOW")
        res = client.get("/api/osv?severity=CRITICAL", headers=HEADERS)
        body = res.json()
        assert body["total"] == 1
        assert body["data"][0]["severity"] == "CRITICAL"

    def test_filter_severity_case_insensitive(self, client, db_session):
        """severity フィルタは大文字小文字を無視すること。"""
        _make_osv(db_session, severity="HIGH")
        res = client.get("/api/osv?severity=high", headers=HEADERS)
        assert res.json()["total"] == 1

    def test_search_by_package_name(self, client, db_session):
        """search パラメータでパッケージ名を検索できること。"""
        _make_osv(db_session, osv_id="GHSA-s1", package_name="requests")
        _make_osv(db_session, osv_id="GHSA-s2", package_name="flask")
        res = client.get("/api/osv?search=requ", headers=HEADERS)
        body = res.json()
        assert body["total"] == 1
        assert body["data"][0]["package_name"] == "requests"

    def test_search_by_osv_id(self, client, db_session):
        """search パラメータで OSV ID を検索できること。"""
        _make_osv(db_session, osv_id="GHSA-abc-1234", package_name="pkg-x")
        _make_osv(db_session, osv_id="GHSA-xyz-5678", package_name="pkg-y")
        res = client.get("/api/osv?search=abc-1234", headers=HEADERS)
        assert res.json()["total"] == 1

    def test_pagination(self, client, db_session):
        """ページネーションが機能すること。"""
        for i in range(5):
            _make_osv(
                db_session,
                osv_id=f"GHSA-page-{i:03d}",
                package_name=f"pkg-{i}",
            )
        res = client.get("/api/osv?per_page=2&page=1", headers=HEADERS)
        body = res.json()
        assert body["total"] == 5
        assert len(body["data"]) == 2
        assert body["page"] == 1
        assert body["per_page"] == 2

    def test_pagination_page2(self, client, db_session):
        """2ページ目が正しく返ること。"""
        for i in range(5):
            _make_osv(
                db_session,
                osv_id=f"GHSA-p2-{i:03d}",
                package_name=f"item-{i}",
            )
        res = client.get("/api/osv?per_page=2&page=2", headers=HEADERS)
        body = res.json()
        assert len(body["data"]) == 2

    def test_days_filter_excludes_old(self, client, db_session):
        """days フィルタで古いデータが除外されること。"""
        old_dt = datetime(2020, 1, 1, tzinfo=UTC)
        _make_osv(db_session, osv_id="GHSA-old-001", modified=old_dt, published=old_dt)
        res = client.get("/api/osv?days=90", headers=HEADERS)
        assert res.json()["total"] == 0

    def test_updated_since_filter(self, client, db_session):
        """updated_since パラメータで差分取得（増分同期）が機能することを確認する。

        SQLite（テストDB）は naive・秒精度で保存・比較するため、insert時刻に依存せず
        両レコードの updated_at を明示的に固定する（本番の PostgreSQL は tz-aware・
        マイクロ秒精度で正しく比較できる）。
        """
        cutoff = datetime(2026, 6, 15, 12, 0, 0)
        old = _make_osv(db_session, osv_id="GHSA-old-updated", package_name="pkg-old")
        new = _make_osv(db_session, osv_id="GHSA-new-updated", package_name="pkg-new")

        db_session.query(OsvVulnerability).filter_by(id=old.id).update(
            {"updated_at": cutoff - timedelta(days=1)}
        )
        db_session.query(OsvVulnerability).filter_by(id=new.id).update(
            {"updated_at": cutoff + timedelta(days=1)}
        )
        db_session.commit()

        res = client.get(
            "/api/osv", params={"updated_since": cutoff.isoformat()}, headers=HEADERS,
        )
        body = res.json()
        assert body["total"] == 1
        assert body["data"][0]["osv_id"] == "GHSA-new-updated"

    def test_sort_by_cvss(self, client, db_session):
        """sort_by=cvss 指定時に CVSS スコア降順でソートされること。"""
        _make_osv(db_session, osv_id="GHSA-cvss-low", package_name="pkg-low", cvss_score=4.0)
        _make_osv(db_session, osv_id="GHSA-cvss-high", package_name="pkg-high", cvss_score=9.8)
        _make_osv(db_session, osv_id="GHSA-cvss-mid", package_name="pkg-mid", cvss_score=7.5)
        res = client.get("/api/osv?sort_by=cvss", headers=HEADERS)
        body = res.json()
        scores = [item["cvss_score"] for item in body["data"]]
        # CVSS スコアが降順になっていること
        assert scores == sorted(scores, reverse=True)
        assert scores[0] == 9.8

    def test_sort_by_modified_default(self, client, db_session):
        """sort_by 未指定（デフォルト）は更新日時降順でソートされること。"""
        early = _NOW - timedelta(days=20)
        late = _NOW - timedelta(days=1)
        _make_osv(
            db_session, osv_id="GHSA-mod-early",
            package_name="pkg-a", modified=early, published=early,
        )
        _make_osv(
            db_session, osv_id="GHSA-mod-late",
            package_name="pkg-b", modified=late, published=late,
        )
        res = client.get("/api/osv", headers=HEADERS)
        body = res.json()
        assert body["data"][0]["osv_id"] == "GHSA-mod-late"


# ──────────────────────────────────────────────────────────────
# GET /api/osv/stats
# ──────────────────────────────────────────────────────────────


class TestOsvStats:
    def test_empty(self, client):
        """データがない場合は全て 0 / 空リストを返す。"""
        res = client.get("/api/osv/stats", headers=HEADERS)
        assert res.status_code == 200
        body = res.json()
        assert body["total"] == 0
        assert body["ecosystems"] == []
        assert body["severities"] == []

    def test_requires_auth(self, client):
        res = client.get("/api/osv/stats")
        assert res.status_code == 403

    def test_ecosystem_counts(self, client, db_session):
        """エコシステム別件数が正しく集計されること。"""
        _make_osv(db_session, osv_id="GHSA-e1", ecosystem="PyPI", package_name="a")
        _make_osv(db_session, osv_id="GHSA-e2", ecosystem="PyPI", package_name="b")
        _make_osv(db_session, osv_id="GHSA-e3", ecosystem="npm", package_name="c")
        res = client.get("/api/osv/stats", headers=HEADERS)
        body = res.json()
        assert body["total"] == 3
        eco_map = {e["ecosystem"]: e["count"] for e in body["ecosystems"]}
        assert eco_map["PyPI"] == 2
        assert eco_map["npm"] == 1

    def test_severity_counts(self, client, db_session):
        """重要度別件数が正しく集計されること。"""
        _make_osv(db_session, osv_id="GHSA-sv1", severity="CRITICAL", package_name="a")
        _make_osv(db_session, osv_id="GHSA-sv2", severity="HIGH", package_name="b")
        _make_osv(db_session, osv_id="GHSA-sv3", severity="HIGH", package_name="c")
        res = client.get("/api/osv/stats", headers=HEADERS)
        body = res.json()
        sev_map = {s["severity"]: s["count"] for s in body["severities"]}
        assert sev_map["HIGH"] == 2
        assert sev_map["CRITICAL"] == 1

    def test_monthly_trend(self, client, db_session):
        """月別トレンドが返ること。"""
        _make_osv(db_session, osv_id="GHSA-mt1", package_name="a")
        res = client.get("/api/osv/stats", headers=HEADERS)
        body = res.json()
        assert len(body["monthly_trend"]) >= 1


# ──────────────────────────────────────────────────────────────
# POST /admin/osv-crawl
# ──────────────────────────────────────────────────────────────


class TestAdminOsvCrawl:
    def test_trigger_osv_crawl(self, client):
        """POST /admin/osv-crawl が 202 を返しバックグラウンドで起動すること。"""
        with patch("app.osv.router.fetch_and_store_osv", return_value=(0, 0, 0)):
            res = client.post("/admin/osv-crawl", headers=HEADERS)
        assert res.status_code == 202
        body = res.json()
        assert "background" in body["message"].lower()

    def test_trigger_osv_crawl_requires_auth(self, client):
        """API キーなしは 403 を返すこと。"""
        res = client.post("/admin/osv-crawl")
        assert res.status_code == 403

    def test_force_query_param_is_passed_through(self, client):
        """?force=true が fetch_and_store_osv(force=True) に渡ること（Issue #239）。"""
        with patch(
            "app.osv.router.run_in_background", side_effect=lambda name, fn: fn(),
        ), patch(
            "app.osv.router.fetch_and_store_osv", return_value=(0, 0, 0),
        ) as mock_fetch:
            res = client.post("/admin/osv-crawl?force=true", headers=HEADERS)
        assert res.status_code == 202
        mock_fetch.assert_called_once_with(days=None, force=True)


# ──────────────────────────────────────────────────────────────
# routers/osv.py — PostgreSQL year_month 分岐
# ──────────────────────────────────────────────────────────────


class TestYearMonthExpr:
    def test_postgresql_branch(self):
        """PostgreSQL ダイアレクトの場合に func.to_char を返すこと。"""
        from sqlalchemy import Column, DateTime

        from app.core.db_utils import year_month_expr

        col = Column("published", DateTime)
        with patch("app.core.db_utils.engine") as mock_engine:
            mock_engine.dialect.name = "postgresql"
            result = year_month_expr(col)
        assert "to_char" in str(result).lower()

    def test_sqlite_branch(self):
        """SQLite ダイアレクトの場合に strftime を返すこと。"""
        from sqlalchemy import Column, DateTime

        from app.core.db_utils import year_month_expr

        col = Column("published", DateTime)
        with patch("app.core.db_utils.engine") as mock_engine:
            mock_engine.dialect.name = "sqlite"
            result = year_month_expr(col)
        assert "strftime" in str(result).lower()


# ──────────────────────────────────────────────────────────────
# schemas.py — OsvVulnerabilityOut.model_validate dict フォールバック
# ──────────────────────────────────────────────────────────────


class TestOsvVulnerabilityOutModelValidate:
    def test_validate_from_dict(self):
        """dict（__dict__ なし）から model_validate を呼ぶと super() フォールバックが動くこと。"""
        from app.osv.schemas import OsvVulnerabilityOut

        data = {
            "osv_id": "GHSA-schema-001",
            "ecosystem": "PyPI",
            "package_name": "fastapi",
            "aliases": ["CVE-2026-00001"],
            "summary": "Test vuln",
            "details": None,
            "severity": "HIGH",
            "cvss_score": 7.5,
            "affected_versions": ["1.0.0"],
            "fixed_versions": ["1.1.0"],
            "references": ["https://example.com"],
            "published": "2026-01-01T00:00:00+00:00",
            "modified": "2026-06-01T00:00:00+00:00",
        }
        result = OsvVulnerabilityOut.model_validate(data)
        assert result.osv_id == "GHSA-schema-001"
        assert result.ecosystem == "PyPI"
        assert result.published == "2026-01-01T00:00:00+00:00"

    def test_validate_from_orm_object_includes_fetched_at_and_withdrawn_at(self, db_session):
        """ORMオブジェクト（__dict__あり）経路でも fetched_at/withdrawn_at が欠落しないこと。

        model_validate をORM用にオーバーライドした際、明示的にキーを列挙していない
        フィールドはデフォルト値（None）にフォールバックしてしまう回帰バグの再発防止。
        """
        from app.osv.schemas import OsvVulnerabilityOut

        record = _make_osv(
            db_session,
            osv_id="GHSA-fetched-serialize",
            withdrawn_at=datetime(2026, 2, 1, tzinfo=UTC),
            fetched_at=datetime(2026, 9, 7, 9, 32, 44, tzinfo=UTC),
        )
        # SQLiteはtz情報を保持せず返すため、日時部分のみ比較する
        result = OsvVulnerabilityOut.model_validate(record)
        dumped = result.model_dump()
        assert dumped["withdrawn_at"].startswith("2026-02-01T00:00:00")
        assert dumped["fetched_at"].startswith("2026-09-07T09:32:44")

    def test_validate_from_orm_object_with_null_fetched_at(self, db_session):
        """fetched_at/withdrawn_at が未取得（None）の場合はnullのまま返ること。"""
        from app.osv.schemas import OsvVulnerabilityOut

        record = _make_osv(db_session, osv_id="GHSA-fetched-null")
        result = OsvVulnerabilityOut.model_validate(record)
        dumped = result.model_dump()
        assert dumped["withdrawn_at"] is None


# ──────────────────────────────────────────────────────────────
# GET /api/osv/{osv_id} — OSV ID 個別取得（Issue #134：STIX拡張）
# ──────────────────────────────────────────────────────────────


class TestGetOsvVulnerability:
    def test_returns_json_by_default(self, client, db_session):
        _make_osv(db_session, osv_id="GHSA-route-0001", package_name="pkg-a")

        res = client.get(
            "/api/osv/GHSA-route-0001", headers={"X-API-KEY": TEST_API_KEY},
        )
        assert res.status_code == 200
        assert "application/json" in res.headers["content-type"]
        body = res.json()
        assert isinstance(body, list)
        assert body[0]["osv_id"] == "GHSA-route-0001"

    def test_returns_multiple_rows_for_same_osv_id_across_packages(self, client, db_session):
        _make_osv(db_session, osv_id="GHSA-multi-0001", ecosystem="PyPI", package_name="pkg-a")
        _make_osv(db_session, osv_id="GHSA-multi-0001", ecosystem="npm", package_name="pkg-b")

        res = client.get(
            "/api/osv/GHSA-multi-0001", headers={"X-API-KEY": TEST_API_KEY},
        )
        assert res.status_code == 200
        assert len(res.json()) == 2

    def test_returns_stix_bundle_format(self, client, db_session):
        _make_osv(db_session, osv_id="GHSA-route-0002", package_name="pkg-c")

        res = client.get(
            "/api/osv/GHSA-route-0002?format=stix", headers={"X-API-KEY": TEST_API_KEY},
        )
        assert res.status_code == 200
        assert res.headers["content-type"] == "application/stix+json;version=2.1"
        body = res.json()
        assert body["type"] == "bundle"
        assert len(body["objects"]) == 1
        assert body["objects"][0]["name"] == "GHSA-route-0002"

    def test_404_for_unknown_osv_id(self, client):
        res = client.get(
            "/api/osv/GHSA-unknown-9999", headers={"X-API-KEY": TEST_API_KEY},
        )
        assert res.status_code == 404

    def test_requires_auth(self, client, db_session):
        _make_osv(db_session, osv_id="GHSA-route-0001", package_name="pkg-a")
        res = client.get("/api/osv/GHSA-route-0001")
        assert res.status_code == 403
