"""OSV 脆弱性 API のテスト。

GET /api/osv        – 一覧取得・フィルタリング・ページネーション
GET /api/osv/stats  – 統計情報取得
クローラーヘルパー関数・API クライアントのユニットテスト
"""
import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

import httpx  # noqa: E402

from app.cron_osv import (  # noqa: E402
    _build_records,
    _extract_fixed_versions,
    _fetch_vuln_by_id,
    _parse_severity,
    _query_packages_batch,
    _upsert_osv_records,
    fetch_and_store_osv,
)
from app.models import OsvVulnerability  # noqa: E402

TEST_API_KEY = "test-api-key-for-pytest"
HEADERS = {"X-API-KEY": TEST_API_KEY}

# テスト用の OSV エントリを生成するヘルパー
_NOW = datetime(2026, 6, 15, 0, 0, 0, tzinfo=timezone.utc)


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
        old_dt = datetime(2020, 1, 1, tzinfo=timezone.utc)
        _make_osv(db_session, osv_id="GHSA-old-001", modified=old_dt, published=old_dt)
        res = client.get("/api/osv?days=90", headers=HEADERS)
        assert res.json()["total"] == 0


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
# クローラーヘルパー関数のユニットテスト
# ──────────────────────────────────────────────────────────────


class TestParseSeverity:
    def test_database_specific_critical(self):
        """database_specific.severity=CRITICAL を正しく抽出する。"""
        vuln = {"database_specific": {"severity": "CRITICAL"}}
        sev, score = _parse_severity(vuln)
        assert sev == "CRITICAL"
        assert score is None

    def test_database_specific_with_cvss_score(self):
        """database_specific.cvss.score も合わせて抽出する。"""
        vuln = {
            "database_specific": {
                "severity": "HIGH",
                "cvss": {"score": 8.1},
            }
        }
        sev, score = _parse_severity(vuln)
        assert sev == "HIGH"
        assert score == 8.1

    def test_database_specific_lowercase(self):
        """severity が小文字でも UPPER に変換して返す。"""
        vuln = {"database_specific": {"severity": "medium"}}
        sev, score = _parse_severity(vuln)
        assert sev == "MEDIUM"

    def test_numeric_score_critical(self):
        """severity[].score が 9.0 以上なら CRITICAL。"""
        vuln = {"severity": [{"type": "CVSS_V3", "score": "9.8"}]}
        sev, score = _parse_severity(vuln)
        assert sev == "CRITICAL"
        assert score == 9.8

    def test_numeric_score_high(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "7.5"}]}
        sev, score = _parse_severity(vuln)
        assert sev == "HIGH"
        assert score == 7.5

    def test_numeric_score_medium(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "5.0"}]}
        sev, score = _parse_severity(vuln)
        assert sev == "MEDIUM"

    def test_numeric_score_low(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "2.0"}]}
        sev, score = _parse_severity(vuln)
        assert sev == "LOW"

    def test_no_severity(self):
        """severity 情報がない場合は (None, None) を返す。"""
        sev, score = _parse_severity({})
        assert sev is None
        assert score is None

    def test_non_numeric_score_returns_none(self):
        """CVSS ベクター文字列（数値でない）の場合は None を返す。"""
        vuln = {
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/..."}]
        }
        sev, score = _parse_severity(vuln)
        assert sev is None
        assert score is None


class TestParseSeverityEdgeCases:
    def test_cvss_score_type_error(self):
        """cvss.score が変換不能な型の場合は None を返す。"""
        vuln = {
            "database_specific": {
                "severity": "HIGH",
                "cvss": {"score": None},
            }
        }
        sev, score = _parse_severity(vuln)
        assert sev == "HIGH"
        assert score is None

    def test_cvss_score_value_error(self):
        """cvss.score が文字列で数値変換できない場合は None を返す。"""
        vuln = {
            "database_specific": {
                "severity": "HIGH",
                "cvss": {"score": "not-a-number"},
            }
        }
        sev, score = _parse_severity(vuln)
        assert sev == "HIGH"
        assert score is None


class TestExtractFixedVersions:
    def test_basic(self):
        affected = {
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}
            ]
        }
        assert _extract_fixed_versions(affected) == ["1.2.3"]

    def test_multiple_fixed(self):
        affected = {
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "1.0.0"},
                        {"introduced": "2.0.0"},
                        {"fixed": "2.1.0"},
                    ],
                }
            ]
        }
        assert _extract_fixed_versions(affected) == ["1.0.0", "2.1.0"]

    def test_no_ranges(self):
        assert _extract_fixed_versions({}) == []

    def test_no_fixed_event(self):
        affected = {
            "ranges": [{"type": "GIT", "events": [{"introduced": "abc123"}]}]
        }
        assert _extract_fixed_versions(affected) == []


class TestBuildRecords:
    def _vuln(self, **kwargs):
        base = {
            "id": "GHSA-xxxx-0001",
            "published": "2026-01-01T00:00:00Z",
            "modified": "2026-06-01T00:00:00Z",
            "aliases": ["CVE-2026-00001"],
            "summary": "A test vulnerability",
            "details": "Detailed description",
            "severity": [{"type": "CVSS_V3", "score": "8.5"}],
            "affected": [
                {
                    "package": {"name": "requests", "ecosystem": "PyPI"},
                    "versions": ["2.0.0", "2.1.0"],
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"fixed": "2.2.0"}]}
                    ],
                }
            ],
            "references": [
                {"url": "https://example.com/advisory"},
                {"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-00001"},
            ],
        }
        base.update(kwargs)
        return base

    def test_basic_record(self):
        modified = datetime(2026, 6, 1, tzinfo=timezone.utc)
        records = _build_records(self._vuln(), modified)
        assert len(records) == 1
        r = records[0]
        assert r["osv_id"] == "GHSA-xxxx-0001"
        assert r["ecosystem"] == "PyPI"
        assert r["package_name"] == "requests"
        assert r["aliases"] == ["CVE-2026-00001"]
        assert r["severity"] == "HIGH"
        assert r["fixed_versions"] == ["2.2.0"]
        assert r["affected_versions"] == ["2.0.0", "2.1.0"]
        assert len(r["references"]) == 2

    def test_multiple_packages(self):
        """1エントリで複数パッケージに影響する場合は複数レコードを生成する。"""
        vuln = self._vuln()
        vuln["affected"] = [
            {"package": {"name": "pkg-a", "ecosystem": "PyPI"}, "versions": [], "ranges": []},
            {"package": {"name": "pkg-b", "ecosystem": "npm"}, "versions": [], "ranges": []},
        ]
        modified = datetime(2026, 6, 1, tzinfo=timezone.utc)
        records = _build_records(vuln, modified)
        assert len(records) == 2
        ecosystems = {r["ecosystem"] for r in records}
        assert ecosystems == {"PyPI", "npm"}

    def test_references_limited_to_5(self):
        """参考リンクは最大 5 件に制限されること。"""
        vuln = self._vuln()
        vuln["references"] = [{"url": f"https://example.com/{i}"} for i in range(10)]
        modified = datetime(2026, 6, 1, tzinfo=timezone.utc)
        records = _build_records(vuln, modified)
        assert len(records[0]["references"]) == 5

    def test_affected_versions_limited_to_30(self):
        """影響バージョンは最大 30 件に制限されること。"""
        vuln = self._vuln()
        vuln["affected"][0]["versions"] = [str(i) for i in range(50)]
        modified = datetime(2026, 6, 1, tzinfo=timezone.utc)
        records = _build_records(vuln, modified)
        assert len(records[0]["affected_versions"]) == 30

    def test_no_affected_returns_empty(self):
        """affected が空の場合はレコードなし。"""
        vuln = self._vuln()
        vuln["affected"] = []
        modified = datetime(2026, 6, 1, tzinfo=timezone.utc)
        records = _build_records(vuln, modified)
        assert records == []


class TestBuildRecordsEdgeCases:
    def test_invalid_published_falls_back_to_modified(self):
        """published が不正な場合は modified で代替されること。"""
        modified = datetime(2026, 6, 1, tzinfo=timezone.utc)
        vuln = {
            "id": "GHSA-pub-err",
            "published": "not-a-valid-date",
            "aliases": [],
            "summary": "Test",
            "affected": [
                {"package": {"name": "pkg", "ecosystem": "PyPI"},
                 "versions": [], "ranges": []}
            ],
            "references": [],
        }
        records = _build_records(vuln, modified)
        assert len(records) == 1
        assert records[0]["published"] == modified

    def test_missing_pkg_name_skipped(self):
        """パッケージ名が空の affected エントリはスキップされること。"""
        modified = datetime(2026, 6, 1, tzinfo=timezone.utc)
        vuln = {
            "id": "GHSA-no-name",
            "published": "2026-06-01T00:00:00Z",
            "aliases": [],
            "summary": "Test",
            "affected": [
                {"package": {"name": "", "ecosystem": "PyPI"},
                 "versions": [], "ranges": []},
                {"package": {"name": "valid-pkg", "ecosystem": "PyPI"},
                 "versions": [], "ranges": []},
            ],
            "references": [],
        }
        records = _build_records(vuln, modified)
        assert len(records) == 1
        assert records[0]["package_name"] == "valid-pkg"

    def test_missing_ecosystem_skipped(self):
        """エコシステムが空の affected エントリはスキップされること。"""
        modified = datetime(2026, 6, 1, tzinfo=timezone.utc)
        vuln = {
            "id": "GHSA-no-eco",
            "published": "2026-06-01T00:00:00Z",
            "aliases": [],
            "summary": "Test",
            "affected": [
                {"package": {"name": "pkg", "ecosystem": ""},
                 "versions": [], "ranges": []},
            ],
            "references": [],
        }
        records = _build_records(vuln, modified)
        assert records == []


# ──────────────────────────────────────────────────────────────
# OSV API クライアント (_query_packages_batch)
# ──────────────────────────────────────────────────────────────


def _mock_batch_response(vulns_per_query: list[list[dict]]) -> MagicMock:
    """_query_packages_batch が呼ぶ httpx.Client のモックを返す。"""
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {
        "results": [{"vulns": v} for v in vulns_per_query]
    }
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.post = MagicMock(return_value=mock_resp)
    return mock_client


class TestQueryPackagesBatch:
    def test_returns_deduped_id_refs(self):
        """同じ ID が複数クエリから返っても1件に絞り込むこと。"""
        ref = {"id": "GHSA-shared", "modified": "2026-06-01T00:00:00Z"}
        mock_client = _mock_batch_response([
            [ref],                                             # query 1
            [ref],                                             # query 2 (重複)
            [{"id": "GHSA-unique", "modified": "2026-06-01T00:00:00Z"}],  # query 3
        ])
        with patch("app.cron_osv.httpx.Client", return_value=mock_client):
            result = _query_packages_batch([
                ("requests", "PyPI"),
                ("flask", "PyPI"),
                ("django", "PyPI"),
            ])
        ids = [v["id"] for v in result]
        assert ids.count("GHSA-shared") == 1
        assert "GHSA-unique" in ids

    def test_empty_packages_returns_empty(self):
        """空リストを渡した場合は API を呼ばず空リストを返すこと。"""
        with patch("app.cron_osv.httpx.Client") as mock_cls:
            result = _query_packages_batch([])
        mock_cls.assert_not_called()
        assert result == []

    def test_http_error_propagates(self):
        """HTTP エラーが発生した場合は例外が伝播すること。"""
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value.raise_for_status.side_effect = (
            httpx.HTTPStatusError("503", request=MagicMock(), response=MagicMock())
        )

        import pytest as _pytest
        with patch("app.cron_osv.httpx.Client", return_value=mock_client):
            with _pytest.raises(httpx.HTTPStatusError):
                _query_packages_batch([("requests", "PyPI")])

    def test_filters_empty_vuln_ids(self):
        """ID が空の脆弱性は除外されること。"""
        mock_client = _mock_batch_response([
            [{"id": "", "modified": "2026-06-01T00:00:00Z"}],
            [{"id": "GHSA-valid", "modified": "2026-06-01T00:00:00Z"}],
        ])
        with patch("app.cron_osv.httpx.Client", return_value=mock_client):
            result = _query_packages_batch([("pkg1", "PyPI"), ("pkg2", "PyPI")])
        assert all(v["id"] for v in result)
        assert any(v["id"] == "GHSA-valid" for v in result)


class TestFetchVulnById:
    def test_returns_full_vuln(self):
        """GET /v1/vulns/{id} が完全な脆弱性オブジェクトを返すこと。"""
        full_vuln = _make_vuln("GHSA-detail-001")
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = full_vuln

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get = MagicMock(return_value=mock_resp)

        with patch("app.cron_osv.httpx.Client", return_value=mock_client):
            result = _fetch_vuln_by_id("GHSA-detail-001")

        assert result["id"] == "GHSA-detail-001"
        assert "affected" in result
        mock_client.get.assert_called_once_with(
            "https://api.osv.dev/v1/vulns/GHSA-detail-001"
        )

    def test_http_error_propagates(self):
        """HTTP エラーが発生した場合は例外が伝播すること。"""
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value.raise_for_status.side_effect = (
            httpx.HTTPStatusError("404", request=MagicMock(), response=MagicMock())
        )

        import pytest as _pytest
        with patch("app.cron_osv.httpx.Client", return_value=mock_client):
            with _pytest.raises(httpx.HTTPStatusError):
                _fetch_vuln_by_id("GHSA-not-found")


# ──────────────────────────────────────────────────────────────
# _upsert_osv_records
# ──────────────────────────────────────────────────────────────


class TestUpsertOsvRecords:
    def _make_rec(self, **kwargs) -> dict:
        dt = datetime(2026, 6, 1, tzinfo=timezone.utc)
        base = {
            "osv_id": "GHSA-upsert-001",
            "ecosystem": "PyPI",
            "package_name": "testpkg",
            "aliases": [],
            "summary": "Test",
            "details": None,
            "severity": "HIGH",
            "cvss_score": 7.5,
            "affected_versions": [],
            "fixed_versions": [],
            "references": [],
            "published": dt,
            "modified": dt,
        }
        base.update(kwargs)
        return base

    def test_insert_new_record(self, db_session):
        """新規レコードが挿入されること。"""
        ins, upd = _upsert_osv_records(db_session, [self._make_rec()])
        assert ins == 1
        assert upd == 0

    def test_update_changed_record(self, db_session):
        """modified が変化した既存レコードが更新されること。"""
        old_dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
        new_dt = datetime(2026, 6, 1, tzinfo=timezone.utc)
        _make_osv(
            db_session,
            osv_id="GHSA-upd-chg",
            package_name="testpkg",
            modified=old_dt,
            published=old_dt,
        )

        rec = self._make_rec(osv_id="GHSA-upd-chg", modified=new_dt, summary="Updated")
        ins, upd = _upsert_osv_records(db_session, [rec])
        assert ins == 0
        assert upd == 1

    def test_no_double_insert(self, db_session):
        """同じキーのレコードを 2 回 upsert しても 2 回 insert されないこと。"""
        rec = self._make_rec(osv_id="GHSA-no-dup-001")
        ins1, _ = _upsert_osv_records(db_session, [rec])
        assert ins1 == 1
        ins2, _ = _upsert_osv_records(db_session, [rec])
        assert ins2 == 0

    def test_empty_records(self, db_session):
        """空リストを渡した場合は 0,0 を返すこと。"""
        ins, upd = _upsert_osv_records(db_session, [])
        assert ins == 0
        assert upd == 0


# ──────────────────────────────────────────────────────────────
# fetch_and_store_osv (メインクローラー)
# ──────────────────────────────────────────────────────────────


def _make_refs(vulns: list[dict]) -> list[dict]:
    """vulns リストから {id, modified} の refs リストを生成する。"""
    return [{"id": v["id"], "modified": v["modified"]} for v in vulns]


class TestFetchAndStoreOsv:
    def test_runs_and_returns_counts(self, db_session):
        """クローラーが正常実行して (inserted, updated) を返すこと。"""
        vuln = _make_vuln("GHSA-mock-0001", modified="2026-06-01T00:00:00Z")

        with patch(
            "app.cron_osv._query_packages_batch",
            return_value=_make_refs([vuln]),
        ):
            with patch(
                "app.cron_osv._fetch_vuln_by_id",
                return_value=vuln,
            ):
                with patch("app.cron_osv.SessionLocal", return_value=db_session):
                    db_session.close = MagicMock()
                    inserted, updated = fetch_and_store_osv()

        assert isinstance(inserted, int)
        assert isinstance(updated, int)

    def test_http_error_skips_ecosystem(self):
        """1エコシステムの querybatch で HTTPError が発生しても処理が継続されること。"""
        call_counts = {"count": 0}

        def batch_side_effect(packages):
            call_counts["count"] += 1
            if call_counts["count"] == 1:
                raise httpx.HTTPError("Connection refused")
            return []

        with patch("app.cron_osv._query_packages_batch", side_effect=batch_side_effect):
            with patch("app.cron_osv.SessionLocal") as mock_sl:
                mock_db = MagicMock()
                mock_db.query.return_value.filter.return_value.first.return_value = None
                mock_sl.return_value = mock_db
                fetch_and_store_osv()

        from app.cron_osv import POPULAR_PACKAGES
        assert call_counts["count"] == len(POPULAR_PACKAGES)

    def test_unexpected_error_skips_ecosystem(self):
        """予期しない例外でも処理が継続されること。"""
        call_counts = {"count": 0}

        def batch_side_effect(packages):
            call_counts["count"] += 1
            if call_counts["count"] == 1:
                raise RuntimeError("Unexpected error")
            return []

        with patch("app.cron_osv._query_packages_batch", side_effect=batch_side_effect):
            with patch("app.cron_osv.SessionLocal") as mock_sl:
                mock_db = MagicMock()
                mock_db.query.return_value.filter.return_value.first.return_value = None
                mock_sl.return_value = mock_db
                fetch_and_store_osv()

        from app.cron_osv import POPULAR_PACKAGES
        assert call_counts["count"] == len(POPULAR_PACKAGES)

    def test_old_vulns_filtered_out(self, db_session):
        """cutoff より古い脆弱性はスキップされること（_fetch_vuln_by_id を呼ばない）。"""
        old_ref = {"id": "GHSA-old", "modified": "2000-01-01T00:00:00Z"}

        with patch("app.cron_osv._query_packages_batch", return_value=[old_ref]):
            with patch("app.cron_osv._fetch_vuln_by_id") as mock_fetch:
                with patch("app.cron_osv.SessionLocal", return_value=db_session):
                    db_session.close = MagicMock()
                    inserted, updated = fetch_and_store_osv()

        # 古いのでフェッチされないこと
        mock_fetch.assert_not_called()
        assert inserted == 0
        assert updated == 0

    def test_fetch_error_skips_single_vuln(self, db_session):
        """個別 ID のフェッチ失敗時はその1件をスキップして継続すること。"""
        recent_ref = {"id": "GHSA-fetch-err", "modified": "2026-06-01T00:00:00Z"}

        with patch("app.cron_osv._query_packages_batch", return_value=[recent_ref]):
            with patch(
                "app.cron_osv._fetch_vuln_by_id",
                side_effect=httpx.HTTPError("timeout"),
            ):
                with patch("app.cron_osv.SessionLocal", return_value=db_session):
                    db_session.close = MagicMock()
                    inserted, updated = fetch_and_store_osv()

        assert inserted == 0


# ──────────────────────────────────────────────────────────────
# POST /admin/osv-crawl
# ──────────────────────────────────────────────────────────────


class TestAdminOsvCrawl:
    def test_trigger_osv_crawl(self, client):
        """POST /admin/osv-crawl が正常にレスポンスを返すこと。"""
        with patch("app.cron_osv._query_packages_batch", return_value=[]):
            res = client.post("/admin/osv-crawl", headers=HEADERS)
        assert res.status_code == 200
        body = res.json()
        assert "message" in body
        assert "inserted" in body
        assert "updated" in body

    def test_trigger_osv_crawl_requires_auth(self, client):
        """API キーなしは 403 を返すこと。"""
        res = client.post("/admin/osv-crawl")
        assert res.status_code == 403

    def test_trigger_osv_crawl_with_records(self, client):
        """OSV レコードが挿入される場合も正常に動作すること。"""
        vulns = [
            _make_vuln("GHSA-crawl-0001", modified="2026-06-01T00:00:00Z"),
            _make_vuln("GHSA-crawl-0002", modified="2026-06-01T00:00:00Z",
                       pkg_name="requests"),
        ]
        refs = _make_refs(vulns)

        def fetch_side_effect(osv_id):
            return next(v for v in vulns if v["id"] == osv_id)

        with patch("app.cron_osv._query_packages_batch", return_value=refs):
            with patch("app.cron_osv._fetch_vuln_by_id", side_effect=fetch_side_effect):
                res = client.post("/admin/osv-crawl", headers=HEADERS)
        assert res.status_code == 200
        body = res.json()
        assert body["inserted"] >= 0
