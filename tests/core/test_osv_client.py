"""app.core.osv_client（OSV REST API 汎用クライアント）のユニットテスト。

OSV エコシステムのクロール（app.osv.crawler）と依存ライブラリ脆弱性スキャン
（app.depscan.crawler）の両方から利用される共通ロジックを検証する。
"""
from unittest.mock import MagicMock, patch

import httpx
import pytest

from app.core.osv_client import (
    extract_fixed_versions,
    fetch_vuln_by_id,
    parse_severity,
    query_packages_batch,
    query_versions_batch,
)


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
# parse_severity
# ──────────────────────────────────────────────────────────────


class TestParseSeverity:
    def test_database_specific_critical(self):
        """database_specific.severity=CRITICAL を正しく抽出する。"""
        vuln = {"database_specific": {"severity": "CRITICAL"}}
        sev, score = parse_severity(vuln)
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
        sev, score = parse_severity(vuln)
        assert sev == "HIGH"
        assert score == 8.1

    def test_database_specific_lowercase(self):
        """severity が小文字でも UPPER に変換して返す。"""
        vuln = {"database_specific": {"severity": "medium"}}
        sev, score = parse_severity(vuln)
        assert sev == "MEDIUM"

    def test_numeric_score_critical(self):
        """severity[].score が 9.0 以上なら CRITICAL。"""
        vuln = {"severity": [{"type": "CVSS_V3", "score": "9.8"}]}
        sev, score = parse_severity(vuln)
        assert sev == "CRITICAL"
        assert score == 9.8

    def test_numeric_score_high(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "7.5"}]}
        sev, score = parse_severity(vuln)
        assert sev == "HIGH"
        assert score == 7.5

    def test_numeric_score_medium(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "5.0"}]}
        sev, score = parse_severity(vuln)
        assert sev == "MEDIUM"

    def test_numeric_score_low(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "2.0"}]}
        sev, score = parse_severity(vuln)
        assert sev == "LOW"

    def test_no_severity(self):
        """severity 情報がない場合は (None, None) を返す。"""
        sev, score = parse_severity({})
        assert sev is None
        assert score is None

    def test_non_numeric_score_returns_none(self):
        """CVSS ベクター文字列（数値でない）の場合は None を返す。"""
        vuln = {
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/..."}]
        }
        sev, score = parse_severity(vuln)
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
        sev, score = parse_severity(vuln)
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
        sev, score = parse_severity(vuln)
        assert sev == "HIGH"
        assert score is None


# ──────────────────────────────────────────────────────────────
# extract_fixed_versions
# ──────────────────────────────────────────────────────────────


class TestExtractFixedVersions:
    def test_basic(self):
        affected = {
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}
            ]
        }
        assert extract_fixed_versions(affected) == ["1.2.3"]

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
        assert extract_fixed_versions(affected) == ["1.0.0", "2.1.0"]

    def test_no_ranges(self):
        assert extract_fixed_versions({}) == []

    def test_no_fixed_event(self):
        affected = {
            "ranges": [{"type": "GIT", "events": [{"introduced": "abc123"}]}]
        }
        assert extract_fixed_versions(affected) == []


# ──────────────────────────────────────────────────────────────
# query_packages_batch
# ──────────────────────────────────────────────────────────────


def _mock_batch_response(vulns_per_query: list[list[dict]]) -> MagicMock:
    """query_packages_batch が呼ぶ httpx.Client のモックを返す。"""
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
        with patch("app.core.osv_client.httpx.Client", return_value=mock_client):
            result = query_packages_batch([
                ("requests", "PyPI"),
                ("flask", "PyPI"),
                ("django", "PyPI"),
            ])
        ids = [v["id"] for v in result]
        assert ids.count("GHSA-shared") == 1
        assert "GHSA-unique" in ids

    def test_empty_packages_returns_empty(self):
        """空リストを渡した場合は API を呼ばず空リストを返すこと。"""
        with patch("app.core.osv_client.httpx.Client") as mock_cls:
            result = query_packages_batch([])
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

        with patch("app.core.osv_client.httpx.Client", return_value=mock_client):
            with pytest.raises(httpx.HTTPStatusError):
                query_packages_batch([("requests", "PyPI")])

    def test_filters_empty_vuln_ids(self):
        """ID が空の脆弱性は除外されること。"""
        mock_client = _mock_batch_response([
            [{"id": "", "modified": "2026-06-01T00:00:00Z"}],
            [{"id": "GHSA-valid", "modified": "2026-06-01T00:00:00Z"}],
        ])
        with patch("app.core.osv_client.httpx.Client", return_value=mock_client):
            result = query_packages_batch([("pkg1", "PyPI"), ("pkg2", "PyPI")])
        assert all(v["id"] for v in result)
        assert any(v["id"] == "GHSA-valid" for v in result)


# ──────────────────────────────────────────────────────────────
# query_versions_batch
# ──────────────────────────────────────────────────────────────


def _mock_httpx_client(post_return=None) -> MagicMock:
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    if post_return is not None:
        mock_client.post = MagicMock(return_value=post_return)
    return mock_client


def _mock_response(json_data) -> MagicMock:
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = json_data
    return resp


class TestQueryVersionsBatch:
    def test_maps_hits_by_position(self):
        results = [{"vulns": [{"id": "GHSA-a"}]}, {"vulns": []}]
        mock_client = _mock_httpx_client(post_return=_mock_response({"results": results}))
        with patch("app.core.osv_client.httpx.Client", return_value=mock_client):
            hits = query_versions_batch([
                ("PyPI", "cryptography", "3.4.7"),
                ("PyPI", "safe-pkg", "1.0.0"),
            ])
        assert hits == {("PyPI", "cryptography", "3.4.7"): ["GHSA-a"]}

    def test_empty_items_returns_empty(self):
        with patch("app.core.osv_client.httpx.Client") as mock_cls:
            result = query_versions_batch([])
        mock_cls.assert_not_called()
        assert result == {}


# ──────────────────────────────────────────────────────────────
# fetch_vuln_by_id
# ──────────────────────────────────────────────────────────────


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

        with patch("app.core.osv_client.httpx.Client", return_value=mock_client):
            result = fetch_vuln_by_id("GHSA-detail-001")

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

        with patch("app.core.osv_client.httpx.Client", return_value=mock_client):
            with pytest.raises(httpx.HTTPStatusError):
                fetch_vuln_by_id("GHSA-not-found")
