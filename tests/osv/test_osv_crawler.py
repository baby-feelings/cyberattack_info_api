"""OSV クローラー（レコード組み立て・保存・取得・古い記録の削除）とモデルのテスト。
"""
import os
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

import httpx  # noqa: E402

from app.osv.crawler import (  # noqa: E402
    _build_records,
    _delete_old_osv_records,
    _upsert_osv_records,
    fetch_and_store_osv,
)
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
        modified = datetime(2026, 6, 1, tzinfo=UTC)
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
        assert r["withdrawn_at"] is None
        assert r["fetched_at"] is not None

    def test_withdrawn_field_is_parsed(self):
        """OSVスキーマのwithdrawnフィールド（撤回日時）がパースされること。"""
        vuln = self._vuln(withdrawn="2026-07-15T00:00:00Z")
        modified = datetime(2026, 6, 1, tzinfo=UTC)
        records = _build_records(vuln, modified)
        assert records[0]["withdrawn_at"] == datetime(2026, 7, 15, tzinfo=UTC)

    def test_malformed_withdrawn_field_is_ignored(self):
        """withdrawnが不正な形式の場合はNoneとして扱う。"""
        vuln = self._vuln(withdrawn="not-a-date")
        modified = datetime(2026, 6, 1, tzinfo=UTC)
        records = _build_records(vuln, modified)
        assert records[0]["withdrawn_at"] is None

    def test_multiple_packages(self):
        """1エントリで複数パッケージに影響する場合は複数レコードを生成する。"""
        vuln = self._vuln()
        vuln["affected"] = [
            {"package": {"name": "pkg-a", "ecosystem": "PyPI"}, "versions": [], "ranges": []},
            {"package": {"name": "pkg-b", "ecosystem": "npm"}, "versions": [], "ranges": []},
        ]
        modified = datetime(2026, 6, 1, tzinfo=UTC)
        records = _build_records(vuln, modified)
        assert len(records) == 2
        ecosystems = {r["ecosystem"] for r in records}
        assert ecosystems == {"PyPI", "npm"}

    def test_references_limited_to_5(self):
        """参考リンクは最大 5 件に制限されること。"""
        vuln = self._vuln()
        vuln["references"] = [{"url": f"https://example.com/{i}"} for i in range(10)]
        modified = datetime(2026, 6, 1, tzinfo=UTC)
        records = _build_records(vuln, modified)
        assert len(records[0]["references"]) == 5

    def test_affected_versions_limited_to_30(self):
        """影響バージョンは最大 30 件に制限されること。"""
        vuln = self._vuln()
        vuln["affected"][0]["versions"] = [str(i) for i in range(50)]
        modified = datetime(2026, 6, 1, tzinfo=UTC)
        records = _build_records(vuln, modified)
        assert len(records[0]["affected_versions"]) == 30

    def test_no_affected_returns_empty(self):
        """affected が空の場合はレコードなし。"""
        vuln = self._vuln()
        vuln["affected"] = []
        modified = datetime(2026, 6, 1, tzinfo=UTC)
        records = _build_records(vuln, modified)
        assert records == []


class TestBuildRecordsEdgeCases:
    def test_invalid_published_falls_back_to_modified(self):
        """published が不正な場合は modified で代替されること。"""
        modified = datetime(2026, 6, 1, tzinfo=UTC)
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
        modified = datetime(2026, 6, 1, tzinfo=UTC)
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
        modified = datetime(2026, 6, 1, tzinfo=UTC)
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
# _upsert_osv_records
# ──────────────────────────────────────────────────────────────


class TestUpsertOsvRecords:
    def _make_rec(self, **kwargs) -> dict:
        dt = datetime(2026, 6, 1, tzinfo=UTC)
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
            "withdrawn_at": None,
            "fetched_at": dt,
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
        old_dt = datetime(2026, 1, 1, tzinfo=UTC)
        new_dt = datetime(2026, 6, 1, tzinfo=UTC)
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

    def test_fetched_at_refreshed_even_when_unchanged(self, db_session):
        """modified が変化していなくても、fetched_atは毎回のクロールで更新されることを確認する。"""
        old_dt = datetime(2026, 1, 1, tzinfo=UTC)
        record = _make_osv(
            db_session, osv_id="GHSA-fetched-refresh", package_name="testpkg",
            modified=old_dt, published=old_dt, fetched_at=old_dt,
        )

        new_fetched_at = datetime(2026, 6, 1, tzinfo=UTC)
        # SQLite はタイムゾーン情報を保持せず naive で返すため、DBから読み戻した
        # modified をそのまま使い、tzinfo有無の差で不等号判定されないようにする
        rec = self._make_rec(
            osv_id="GHSA-fetched-refresh", modified=record.modified, fetched_at=new_fetched_at,
        )
        ins, upd = _upsert_osv_records(db_session, [rec])
        db_session.refresh(record)

        assert ins == 0
        assert upd == 0  # modified は変化していないので updated 扱いにはならない
        # SQLite はタイムゾーン情報を保持せず naive で返す（PostgreSQL は保持する）ため、
        # tzinfo を外して、時刻だけを比較する
        assert record.fetched_at.replace(tzinfo=None) == new_fetched_at.replace(tzinfo=None)

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
        """クローラーが正常実行して (inserted, updated, deleted) を返すこと。"""
        vuln = _make_vuln("GHSA-mock-0001", modified="2026-06-01T00:00:00Z")

        with patch(
            "app.osv.crawler.query_packages_batch",
            return_value=_make_refs([vuln]),
        ):
            with patch(
                "app.osv.crawler.fetch_vuln_by_id",
                return_value=vuln,
            ):
                with patch("app.core.runner.crawler_runner.SessionLocal", return_value=db_session):
                    db_session.close = MagicMock()
                    inserted, updated, deleted = fetch_and_store_osv()

        assert isinstance(inserted, int)
        assert isinstance(updated, int)
        assert isinstance(deleted, int)

    def test_http_error_skips_ecosystem(self):
        """1エコシステムの querybatch で HTTPError が発生しても処理が継続されること。"""
        call_counts = {"count": 0}

        def batch_side_effect(packages):
            call_counts["count"] += 1
            if call_counts["count"] == 1:
                raise httpx.HTTPError("Connection refused")
            return []

        with patch("app.osv.crawler.query_packages_batch", side_effect=batch_side_effect):
            with patch("app.core.runner.crawler_runner.SessionLocal") as mock_sl:
                mock_db = MagicMock()
                mock_db.query.return_value.filter.return_value.first.return_value = None
                mock_sl.return_value = mock_db
                fetch_and_store_osv()

        from app.osv.crawler import POPULAR_PACKAGES
        assert call_counts["count"] == len(POPULAR_PACKAGES)

    def test_unexpected_error_skips_ecosystem(self):
        """予期しない例外でも処理が継続されること。"""
        call_counts = {"count": 0}

        def batch_side_effect(packages):
            call_counts["count"] += 1
            if call_counts["count"] == 1:
                raise RuntimeError("Unexpected error")
            return []

        with patch("app.osv.crawler.query_packages_batch", side_effect=batch_side_effect):
            with patch("app.core.runner.crawler_runner.SessionLocal") as mock_sl:
                mock_db = MagicMock()
                mock_db.query.return_value.filter.return_value.first.return_value = None
                mock_sl.return_value = mock_db
                fetch_and_store_osv()

        from app.osv.crawler import POPULAR_PACKAGES
        assert call_counts["count"] == len(POPULAR_PACKAGES)

    def test_old_vulns_filtered_out(self, db_session):
        """cutoff より古い脆弱性はスキップされること（fetch_vuln_by_id を呼ばない）。"""
        old_ref = {"id": "GHSA-old", "modified": "2000-01-01T00:00:00Z"}

        with patch("app.osv.crawler.query_packages_batch", return_value=[old_ref]):
            with patch("app.osv.crawler.fetch_vuln_by_id") as mock_fetch:
                with patch("app.core.runner.crawler_runner.SessionLocal", return_value=db_session):
                    db_session.close = MagicMock()
                    inserted, updated, deleted = fetch_and_store_osv()

        # 古いのでフェッチされないこと
        mock_fetch.assert_not_called()
        assert inserted == 0
        assert updated == 0

    def test_fetch_error_skips_single_vuln(self, db_session):
        """個別 ID のフェッチ失敗時はその1件をスキップして継続すること。"""
        recent_ref = {"id": "GHSA-fetch-err", "modified": "2026-06-01T00:00:00Z"}

        with patch("app.osv.crawler.query_packages_batch", return_value=[recent_ref]):
            with patch(
                "app.osv.crawler.fetch_vuln_by_id",
                side_effect=httpx.HTTPError("timeout"),
            ):
                with patch("app.core.runner.crawler_runner.SessionLocal", return_value=db_session):
                    db_session.close = MagicMock()
                    inserted, updated, deleted = fetch_and_store_osv()

        assert inserted == 0


# ──────────────────────────────────────────────────────────────
# _delete_old_osv_records
# ──────────────────────────────────────────────────────────────


class TestDeleteOldOsvRecords:
    def test_deletes_old_records(self, db_session):
        """保持期間（OSV_RETENTION_DAYS）を超えた古いレコードが削除されること。"""
        old_dt = datetime(2000, 1, 1, tzinfo=UTC)
        _make_osv(db_session, osv_id="GHSA-old-del-001", modified=old_dt, published=old_dt)
        count_before = db_session.query(OsvVulnerability).count()
        assert count_before == 1

        deleted = _delete_old_osv_records(db_session)

        assert deleted == 1
        count_after = db_session.query(OsvVulnerability).count()
        assert count_after == 0

    def test_keeps_recent_records(self, db_session):
        """保持期間内の新しいレコードは削除されないこと。"""
        recent_dt = datetime(2026, 6, 1, tzinfo=UTC)
        _make_osv(db_session, osv_id="GHSA-recent-keep", modified=recent_dt, published=recent_dt)

        deleted = _delete_old_osv_records(db_session)

        assert deleted == 0
        count_after = db_session.query(OsvVulnerability).count()
        assert count_after == 1

    def test_mixed_records(self, db_session):
        """古いレコードのみ削除され、新しいレコードは残ること。"""
        old_dt = datetime(2000, 1, 1, tzinfo=UTC)
        recent_dt = datetime(2026, 6, 1, tzinfo=UTC)
        _make_osv(db_session, osv_id="GHSA-old-mix", modified=old_dt, published=old_dt)
        _make_osv(
            db_session,
            osv_id="GHSA-recent-mix",
            package_name="requests",
            modified=recent_dt,
            published=recent_dt,
        )

        deleted = _delete_old_osv_records(db_session)

        assert deleted == 1
        remaining = db_session.query(OsvVulnerability).all()
        assert len(remaining) == 1
        assert remaining[0].osv_id == "GHSA-recent-mix"

    def test_empty_db_returns_zero(self, db_session):
        """DB が空の場合は 0 を返すこと。"""
        deleted = _delete_old_osv_records(db_session)
        assert deleted == 0


# ──────────────────────────────────────────────────────────────
# _upsert_osv_records — コミット失敗パス
# ──────────────────────────────────────────────────────────────


class TestUpsertOsvRecordsCommitFailure:
    """_upsert_osv_records の定期コミット・最終コミット失敗パスをカバーする。"""

    def _make_rec(self, osv_id="GHSA-cf-001", pkg="testpkg", **kwargs) -> dict:
        dt = datetime(2026, 6, 1, tzinfo=UTC)
        base = {
            "osv_id": osv_id,
            "ecosystem": "PyPI",
            "package_name": pkg,
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
            "withdrawn_at": None,
            "fetched_at": dt,
        }
        base.update(kwargs)
        return base

    def test_periodic_commit_failure_raises(self):
        """定期コミット（_COMMIT_EVERY 件目）が失敗した場合に rollback して例外が伝播すること。"""
        import pytest as _pytest

        from app.osv.crawler import _COMMIT_EVERY

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None
        mock_db.commit.side_effect = Exception("periodic commit failed")

        # _COMMIT_EVERY 件以上のレコードで定期コミットを発火させる
        records = [
            self._make_rec(osv_id=f"GHSA-pc-{i:04d}", pkg=f"pkg{i}")
            for i in range(_COMMIT_EVERY + 1)
        ]

        with patch("app.osv.crawler._COMMIT_EVERY", 1):
            with _pytest.raises(Exception, match="periodic commit failed"):
                _upsert_osv_records(mock_db, records)

        mock_db.rollback.assert_called()

    def test_final_commit_failure_raises(self):
        """最終コミットが失敗した場合に rollback して例外が伝播すること。"""
        import pytest as _pytest

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = None
        mock_db.commit.side_effect = Exception("final commit failed")

        records = [self._make_rec()]  # 1件のみ→定期コミットは発火しない

        with _pytest.raises(Exception, match="final commit failed"):
            _upsert_osv_records(mock_db, records)

        mock_db.rollback.assert_called()


# ──────────────────────────────────────────────────────────────
# fetch_and_store_osv — 追加カバレッジ
# ──────────────────────────────────────────────────────────────


class TestFetchAndStoreOsvAdditional:
    def test_malformed_modified_date_skipped(self, db_session):
        """modified が不正な日付形式の場合はそのレコードをスキップすること。"""
        bad_ref = {"id": "GHSA-bad-date", "modified": "not-a-valid-date"}

        with patch("app.osv.crawler.query_packages_batch", return_value=[bad_ref]):
            with patch("app.osv.crawler.fetch_vuln_by_id") as mock_fetch:
                with patch("app.core.runner.crawler_runner.SessionLocal", return_value=db_session):
                    db_session.close = MagicMock()
                    inserted, updated, deleted = fetch_and_store_osv()

        # 不正な日付のため fetch_vuln_by_id は呼ばれない
        mock_fetch.assert_not_called()
        assert inserted == 0

    def test_delete_old_records_failure_logged(self, db_session):
        """_delete_old_osv_records が失敗してもクローラー全体はエラーにならないこと。"""
        with patch("app.osv.crawler.query_packages_batch", return_value=[]):
            with patch(
                "app.osv.crawler._delete_old_osv_records",
                side_effect=Exception("delete failed"),
            ):
                with patch("app.core.runner.crawler_runner.SessionLocal", return_value=db_session):
                    db_session.close = MagicMock()
                    # 例外が外に漏れないことを確認
                    inserted, updated, deleted = fetch_and_store_osv()

        assert deleted == 0

    def test_outer_exception_notifies_slack_and_reraises(self):
        """外側の例外ハンドラが Slack 通知して再 raise すること。"""
        import pytest as _pytest

        class BadPackages:
            def items(self):
                raise RuntimeError("outer error")

        with patch("app.osv.crawler.POPULAR_PACKAGES", BadPackages()):
            with patch("app.core.runner.crawler_runner.notify_error") as mock_notify:
                with patch("app.core.runner.crawler_runner.SessionLocal") as mock_sl:
                    mock_sl.return_value = MagicMock()
                    with patch(
                        "app.core.runner.crawler_runner.already_succeeded_recently",
                        return_value=False,
                    ):
                        with _pytest.raises(RuntimeError, match="outer error"):
                            fetch_and_store_osv()

        mock_notify.assert_called_once()
        assert "outer error" in mock_notify.call_args[0][1]


# ──────────────────────────────────────────────────────────────
# OsvVulnerability __repr__
# ──────────────────────────────────────────────────────────────


class TestOsvVulnerabilityRepr:
    def test_repr(self, db_session):
        """`__repr__` が osv_id と ecosystem/package_name を含む文字列を返すこと。"""
        record = _make_osv(db_session, osv_id="GHSA-repr-001")
        r = repr(record)
        assert "GHSA-repr-001" in r
        assert "PyPI" in r
        assert "fastapi" in r


class TestOsvRecordHelpers:
    """_build_records から切り出したヘルパーの単体テスト。"""

    def test_parse_osv_datetime_handles_z_suffix_none_and_garbage(self):
        from app.osv.crawler import _parse_osv_datetime

        parsed = _parse_osv_datetime("2026-01-02T03:04:05Z")
        assert parsed is not None and parsed.utcoffset().total_seconds() == 0
        assert _parse_osv_datetime(None) is None
        assert _parse_osv_datetime("") is None
        assert _parse_osv_datetime("not-a-date") is None
        assert _parse_osv_datetime(12345) is None

    def test_common_fields_cap_references_and_fall_back_published_to_modified(self):
        from app.osv.crawler import _vuln_common_fields

        modified = datetime(2026, 2, 1, tzinfo=UTC)
        vuln = {
            "id": "GHSA-x", "aliases": ["CVE-1", "", None],
            "summary": "  s  ", "details": "",
            "references": [{"url": f"https://e/{i}"} for i in range(8)] + [{"x": 1}],
            "published": "broken", "withdrawn": "2026-03-01T00:00:00Z",
        }
        common = _vuln_common_fields(vuln, modified)

        assert common["osv_id"] == "GHSA-x"
        assert common["aliases"] == ["CVE-1"]
        assert common["summary"] == "s"
        assert common["details"] is None
        assert len(common["references"]) == 5
        assert common["published"] == modified  # 不正な published は modified で代替
        assert common["withdrawn_at"] is not None

    def test_build_records_shares_common_fields_across_affected_packages(self):
        modified = datetime(2026, 2, 1, tzinfo=UTC)
        vuln = {
            "id": "GHSA-multi",
            "affected": [
                {"package": {"name": "a", "ecosystem": "npm"}, "versions": ["1"] * 40},
                {"package": {"name": "b", "ecosystem": "PyPI"}},
                {"package": {"name": "", "ecosystem": "npm"}},  # 名前なしは除外
            ],
        }
        records = _build_records(vuln, modified)

        assert [(r["ecosystem"], r["package_name"]) for r in records] == [
            ("npm", "a"), ("PyPI", "b"),
        ]
        assert len(records[0]["affected_versions"]) == 30
        assert records[0]["osv_id"] == records[1]["osv_id"] == "GHSA-multi"
