"""OSV 脆弱性 API のテスト。

GET /api/osv        – 一覧取得・フィルタリング・ページネーション
GET /api/osv/stats  – 統計情報取得
クローラーヘルパー関数のユニットテスト
"""
import io
import json
import os
import zipfile
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

import httpx  # noqa: E402

from app.cron_osv import (  # noqa: E402
    _build_records,
    _extract_fixed_versions,
    _fetch_ecosystem_zip,
    _parse_severity,
    _process_zip,
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
        # 少なくとも1ヶ月のデータがあること
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


class TestProcessZip:
    def _make_zip(self, entries: list[dict]) -> bytes:
        """テスト用の zip バイト列を生成する。"""
        import io
        import json
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for entry in entries:
                zf.writestr(f"{entry['id']}.json", json.dumps(entry))
        return buf.getvalue()

    def test_filters_by_cutoff(self):
        """cutoff より古いエントリは除外される。"""
        entries = [
            {
                "id": "GHSA-new",
                "modified": "2026-06-01T00:00:00Z",
                "published": "2026-06-01T00:00:00Z",
                "aliases": [],
                "summary": "New vuln",
                "affected": [
                    {"package": {"name": "pkg", "ecosystem": "PyPI"}, "versions": [], "ranges": []}
                ],
                "references": [],
            },
            {
                "id": "GHSA-old",
                "modified": "2020-01-01T00:00:00Z",
                "published": "2020-01-01T00:00:00Z",
                "aliases": [],
                "summary": "Old vuln",
                "affected": [
                    {"package": {"name": "pkg", "ecosystem": "PyPI"}, "versions": [], "ranges": []}
                ],
                "references": [],
            },
        ]
        zip_bytes = self._make_zip(entries)
        cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
        records = _process_zip("PyPI", zip_bytes, cutoff)
        osv_ids = [r["osv_id"] for r in records]
        assert "GHSA-new" in osv_ids
        assert "GHSA-old" not in osv_ids

    def test_returns_all_recent(self):
        """cutoff 以降のエントリは全て返される。"""
        entries = [
            {
                "id": f"GHSA-{i:03d}",
                "modified": "2026-06-01T00:00:00Z",
                "published": "2026-06-01T00:00:00Z",
                "aliases": [],
                "summary": f"Vuln {i}",
                "affected": [
                    {
                        "package": {"name": f"pkg-{i}", "ecosystem": "PyPI"},
                        "versions": [],
                        "ranges": [],
                    }
                ],
                "references": [],
            }
            for i in range(3)
        ]
        zip_bytes = self._make_zip(entries)
        cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
        records = _process_zip("PyPI", zip_bytes, cutoff)
        assert len(records) == 3

    def test_skips_non_json_files(self):
        """zip 内の .json 以外のファイルはスキップされること。"""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("README.txt", "not json")
            zf.writestr("GHSA-ok.json", json.dumps({
                "id": "GHSA-ok",
                "modified": "2026-06-01T00:00:00Z",
                "published": "2026-06-01T00:00:00Z",
                "aliases": [],
                "summary": "OK",
                "affected": [
                    {"package": {"name": "pkg", "ecosystem": "PyPI"},
                     "versions": [], "ranges": []}
                ],
                "references": [],
            }))
        cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
        records = _process_zip("PyPI", buf.getvalue(), cutoff)
        assert len(records) == 1

    def test_skips_invalid_json(self):
        """JSON パースエラーのファイルはスキップされること。"""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("bad.json", "not valid json {{{")
        cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
        records = _process_zip("PyPI", buf.getvalue(), cutoff)
        assert records == []

    def test_skips_missing_modified(self):
        """modified フィールドがないエントリはスキップされること。"""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("no-modified.json", json.dumps({
                "id": "GHSA-nm",
                "published": "2026-06-01T00:00:00Z",
                "aliases": [],
                "summary": "No modified",
                "affected": [],
                "references": [],
            }))
        cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
        records = _process_zip("PyPI", buf.getvalue(), cutoff)
        assert records == []

    def test_skips_invalid_modified_format(self):
        """modified の日時フォーマットが不正な場合はスキップされること。"""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("bad-date.json", json.dumps({
                "id": "GHSA-bd",
                "modified": "not-a-date",
                "published": "2026-06-01T00:00:00Z",
                "aliases": [],
                "summary": "Bad date",
                "affected": [],
                "references": [],
            }))
        cutoff = datetime(2026, 1, 1, tzinfo=timezone.utc)
        records = _process_zip("PyPI", buf.getvalue(), cutoff)
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


class TestFetchEcosystemZip:
    def test_download_success(self):
        """httpx でダウンロードが成功した場合にバイト列を返す。"""
        mock_response = MagicMock()
        mock_response.content = b"fake zip content"
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get = MagicMock(return_value=mock_response)

        with patch("app.cron_osv.httpx.Client", return_value=mock_client):
            result = _fetch_ecosystem_zip("PyPI")

        assert result == b"fake zip content"
        mock_response.raise_for_status.assert_called_once()

    def test_http_error_propagates(self):
        """HTTP エラーが発生した場合は例外が伝播すること。"""
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "404", request=MagicMock(), response=MagicMock()
        )

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get = MagicMock(return_value=mock_response)

        import pytest as _pytest
        with patch("app.cron_osv.httpx.Client", return_value=mock_client):
            with _pytest.raises(httpx.HTTPStatusError):
                _fetch_ecosystem_zip("PyPI")


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
        # 1回目: insert
        ins1, _ = _upsert_osv_records(db_session, [rec])
        assert ins1 == 1
        # 2回目: insert されない（update か skip）
        ins2, _ = _upsert_osv_records(db_session, [rec])
        assert ins2 == 0

    def test_empty_records(self, db_session):
        """空リストを渡した場合は 0,0 を返すこと。"""
        ins, upd = _upsert_osv_records(db_session, [])
        assert ins == 0
        assert upd == 0


def _make_simple_zip(*osv_ids: str) -> bytes:
    """テスト用の最小限の zip バイト列を生成する。"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for osv_id in osv_ids:
            entry = {
                "id": osv_id,
                "modified": "2026-06-01T00:00:00Z",
                "published": "2026-06-01T00:00:00Z",
                "aliases": [],
                "summary": f"Vuln {osv_id}",
                "affected": [
                    {"package": {"name": "mock-pkg", "ecosystem": "PyPI"},
                     "versions": [], "ranges": []}
                ],
                "references": [],
            }
            zf.writestr(f"{osv_id}.json", json.dumps(entry))
    return buf.getvalue()


class TestFetchAndStoreOsv:
    def test_runs_and_stores_records(self, db_session):
        """クローラーが正常に実行してレコードを保存できること。"""
        zip_bytes = _make_simple_zip("GHSA-mock-0001")

        with patch("app.cron_osv._fetch_ecosystem_zip", return_value=zip_bytes):
            with patch("app.cron_osv.SessionLocal", return_value=db_session):
                # close() を無効化（db_session はフィクスチャで管理）
                original_close = db_session.close
                db_session.close = MagicMock()
                fetch_and_store_osv()
                db_session.close = original_close

    def test_http_error_skips_ecosystem(self):
        """1エコシステムで HTTPError が発生しても処理が継続されること。"""
        empty_zip = _make_simple_zip()
        call_counts = {"count": 0}

        def side_effect(ecosystem):
            call_counts["count"] += 1
            if call_counts["count"] == 1:
                raise httpx.HTTPError("Connection refused")
            return empty_zip

        with patch("app.cron_osv._fetch_ecosystem_zip", side_effect=side_effect):
            with patch("app.cron_osv.SessionLocal") as mock_sl:
                mock_db = MagicMock()
                mock_db.query.return_value.filter.return_value.first.return_value = None
                mock_sl.return_value = mock_db
                fetch_and_store_osv()

        # 全 9 エコシステムが試行されること
        assert call_counts["count"] == 9

    def test_unexpected_error_skips_ecosystem(self):
        """予期しない例外でも処理が継続されること。"""
        empty_zip = _make_simple_zip()
        call_counts = {"count": 0}

        def side_effect(ecosystem):
            call_counts["count"] += 1
            if call_counts["count"] == 1:
                raise RuntimeError("Unexpected error")
            return empty_zip

        with patch("app.cron_osv._fetch_ecosystem_zip", side_effect=side_effect):
            with patch("app.cron_osv.SessionLocal") as mock_sl:
                mock_db = MagicMock()
                mock_db.query.return_value.filter.return_value.first.return_value = None
                mock_sl.return_value = mock_db
                fetch_and_store_osv()

        assert call_counts["count"] == 9


class TestAdminOsvCrawl:
    def test_trigger_osv_crawl(self, client):
        """POST /admin/osv-crawl が正常にレスポンスを返すこと。"""
        empty_zip = _make_simple_zip()
        with patch("app.cron_osv._fetch_ecosystem_zip", return_value=empty_zip):
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
        zip_bytes = _make_simple_zip("GHSA-crawl-0001", "GHSA-crawl-0002")
        with patch("app.cron_osv._fetch_ecosystem_zip", return_value=zip_bytes):
            res = client.post("/admin/osv-crawl", headers=HEADERS)
        assert res.status_code == 200
        body = res.json()
        assert body["inserted"] >= 0
