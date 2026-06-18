"""JVN API エンドポイントおよびクローラーユニットテスト。

外部 MyJVN API への HTTP 通信はモックし、ロジックのみを検証する。
"""
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

from app.models import JvnVulnerability
from tests.conftest import TEST_API_KEY

# ── テストデータ ───────────────────────────────────────────────────

_NOW = datetime(2026, 6, 18, 0, 0, 0, tzinfo=timezone.utc)


def _make_jvn(
    jvndb_id: str = "JVNDB-2026-000001",
    title: str = "テスト脆弱性",
    overview: str = "テスト概要",
    severity: str | None = "High",
    cvss_score: float | None = 9.8,
    date_last_modified: datetime = _NOW,
    date_published: datetime = _NOW,
) -> JvnVulnerability:
    """テスト用 JvnVulnerability インスタンスを生成する。"""
    return JvnVulnerability(
        jvndb_id=jvndb_id,
        title=title,
        overview=overview,
        cve_ids=["CVE-2026-12345"],
        severity=severity,
        cvss_score=cvss_score,
        cvss_vector="AV:N/AC:L/Au:N/C:C/I:C/A:C",
        affected_products=[{"vendor": "TestVendor", "product": "TestProduct", "cpe": ""}],
        references=[],
        jvn_url=f"https://jvndb.jvn.jp/ja/contents/2026/{jvndb_id}.html",
        date_published=date_published,
        date_last_modified=date_last_modified,
    )


# ── API エンドポイントテスト ──────────────────────────────────────


def test_list_jvn_empty(client):
    """データなしの場合は空リストを返す。"""
    resp = client.get("/api/jvn", headers={"X-API-KEY": TEST_API_KEY})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 0
    assert body["data"] == []


def test_list_jvn_returns_records(client, db_session):
    """登録済みデータが一覧に含まれる。"""
    db_session.add(_make_jvn())
    db_session.commit()

    resp = client.get("/api/jvn", headers={"X-API-KEY": TEST_API_KEY})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["data"][0]["jvndb_id"] == "JVNDB-2026-000001"


def test_list_jvn_severity_filter(client, db_session):
    """重要度フィルタが正しく機能する。"""
    db_session.add(_make_jvn(jvndb_id="JVNDB-2026-000001", severity="High"))
    db_session.add(_make_jvn(jvndb_id="JVNDB-2026-000002", severity="Low"))
    db_session.commit()

    resp = client.get("/api/jvn?severity=High", headers={"X-API-KEY": TEST_API_KEY})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["data"][0]["severity"] == "High"


def test_list_jvn_search_filter(client, db_session):
    """キーワード検索フィルタが正しく機能する。"""
    db_session.add(_make_jvn(jvndb_id="JVNDB-2026-000001", title="Apache Log4j RCE"))
    db_session.add(_make_jvn(jvndb_id="JVNDB-2026-000002", title="Windows Buffer Overflow"))
    db_session.commit()

    resp = client.get("/api/jvn?search=Apache", headers={"X-API-KEY": TEST_API_KEY})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert "Apache" in body["data"][0]["title"]


def test_list_jvn_pagination(client, db_session):
    """ページネーションが正しく機能する。"""
    for i in range(5):
        db_session.add(_make_jvn(jvndb_id=f"JVNDB-2026-{i:06d}"))
    db_session.commit()

    resp = client.get("/api/jvn?per_page=2&page=1", headers={"X-API-KEY": TEST_API_KEY})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 5
    assert len(body["data"]) == 2


def test_list_jvn_requires_api_key(client):
    """API キーなしの場合は 403 を返す。"""
    resp = client.get("/api/jvn")
    assert resp.status_code == 403


def test_get_jvn_stats_empty(client):
    """データなしの場合は統計が空で返る。"""
    resp = client.get("/api/jvn/stats", headers={"X-API-KEY": TEST_API_KEY})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 0
    assert body["severities"] == []
    assert body["monthly_trend"] == []


def test_get_jvn_stats_severity_breakdown(client, db_session):
    """重要度別集計が正しく返る。"""
    db_session.add(_make_jvn(jvndb_id="JVNDB-2026-000001", severity="High"))
    db_session.add(_make_jvn(jvndb_id="JVNDB-2026-000002", severity="High"))
    db_session.add(_make_jvn(jvndb_id="JVNDB-2026-000003", severity="Medium"))
    db_session.commit()

    resp = client.get("/api/jvn/stats", headers={"X-API-KEY": TEST_API_KEY})
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 3

    sev_map = {s["severity"]: s["count"] for s in body["severities"]}
    assert sev_map["High"] == 2
    assert sev_map["Medium"] == 1


# ── クローラーユニットテスト ──────────────────────────────────────


def test_strip_html():
    """HTML タグが除去されること。"""
    from app.cron_jvn import _strip_html

    assert _strip_html("<p>テスト</p>") == "テスト"
    assert _strip_html("<a href='#'>リンク</a>テキスト") == "リンクテキスト"
    assert _strip_html("プレーンテキスト") == "プレーンテキスト"


def test_parse_datetime_valid():
    """正常な ISO 8601 日付文字列がパースされること。"""
    from app.cron_jvn import _parse_datetime

    dt = _parse_datetime("2026-06-18T00:00:00+09:00")
    assert dt is not None
    assert dt.year == 2026
    assert dt.month == 6
    assert dt.day == 18


def test_parse_datetime_none():
    """None 入力は None を返すこと。"""
    from app.cron_jvn import _parse_datetime

    assert _parse_datetime(None) is None
    assert _parse_datetime("") is None


def test_parse_datetime_invalid():
    """不正な文字列は None を返すこと。"""
    from app.cron_jvn import _parse_datetime

    assert _parse_datetime("not-a-date") is None


def test_upsert_jvn_insert(db_session):
    """新規エントリが挿入されること。"""
    from app.cron_jvn import _upsert_jvn

    entries = [
        {
            "jvndb_id": "JVNDB-2026-999001",
            "title": "テスト脆弱性",
            "overview": "概要",
            "cve_ids": ["CVE-2026-99999"],
            "severity": "High",
            "cvss_score": 9.8,
            "cvss_vector": "AV:N",
            "affected_products": [],
            "references": [],
            "jvn_url": "https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-999001.html",
            "date_published": _NOW,
            "date_last_modified": _NOW,
        }
    ]
    inserted, updated = _upsert_jvn(db_session, entries)
    assert inserted == 1
    assert updated == 0

    record = db_session.query(JvnVulnerability).filter_by(jvndb_id="JVNDB-2026-999001").first()
    assert record is not None
    assert record.severity == "High"


def test_upsert_jvn_update(db_session):
    """既存エントリが更新されること。"""
    from app.cron_jvn import _upsert_jvn

    db_session.add(_make_jvn(jvndb_id="JVNDB-2026-999002", title="旧タイトル"))
    db_session.commit()

    new_modified = datetime(2026, 6, 19, 0, 0, 0, tzinfo=timezone.utc)
    entries = [
        {
            "jvndb_id": "JVNDB-2026-999002",
            "title": "新タイトル",
            "overview": "更新概要",
            "cve_ids": [],
            "severity": "Medium",
            "cvss_score": 5.0,
            "cvss_vector": None,
            "affected_products": [],
            "references": [],
            "jvn_url": "https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-999002.html",
            "date_published": _NOW,
            "date_last_modified": new_modified,
        }
    ]
    inserted, updated = _upsert_jvn(db_session, entries)
    assert inserted == 0
    assert updated == 1

    record = db_session.query(JvnVulnerability).filter_by(jvndb_id="JVNDB-2026-999002").first()
    assert record is not None
    assert record.title == "新タイトル"


def test_upsert_jvn_deduplicates(db_session):
    """リスト内の jvndb_id 重複が除去されること。"""
    from app.cron_jvn import _upsert_jvn

    entry = {
        "jvndb_id": "JVNDB-2026-999003",
        "title": "重複テスト",
        "overview": "概要",
        "cve_ids": [],
        "severity": None,
        "cvss_score": None,
        "cvss_vector": None,
        "affected_products": [],
        "references": [],
        "jvn_url": "https://jvndb.jvn.jp/",
        "date_published": _NOW,
        "date_last_modified": _NOW,
    }
    # 同じエントリを2件渡す
    inserted, updated = _upsert_jvn(db_session, [entry, dict(entry)])
    assert inserted == 1  # 1件のみ挿入


def test_fetch_and_store_jvn_success(monkeypatch):
    """クローラーが正常終了し (inserted, updated) を返すこと。"""
    monkeypatch.setattr("app.cron_jvn._fetch_all_entries", lambda cutoff_date: [])
    monkeypatch.setattr("app.cron_jvn.write_crawler_log", lambda *a, **kw: None)
    monkeypatch.setattr(
        "app.cron_jvn.notify_jvn_new_vulnerabilities", lambda **kw: None
    )

    from app.cron_jvn import fetch_and_store_jvn

    inserted, updated = fetch_and_store_jvn()
    assert inserted == 0
    assert updated == 0


def test_fetch_and_store_jvn_error(monkeypatch):
    """クローラーが例外を発生させた場合に再 raise され、エラーログが書かれること。"""
    monkeypatch.setattr(
        "app.cron_jvn._fetch_all_entries",
        lambda cutoff_date: (_ for _ in ()).throw(RuntimeError("API down")),  # type: ignore[arg-type]
    )
    monkeypatch.setattr("app.cron_jvn.write_crawler_log", lambda *a, **kw: None)
    monkeypatch.setattr("app.cron_jvn.notify_jvn_crawl_error", lambda *a, **kw: None)

    from app.cron_jvn import fetch_and_store_jvn

    with pytest.raises(RuntimeError, match="API down"):
        fetch_and_store_jvn()


def test_parse_item_skips_non_jvndb(monkeypatch):
    """JVNDB- で始まらない identifier はスキップされること。"""
    import defusedxml.ElementTree as ET

    from app.cron_jvn import _parse_item

    xml_str = """<item xmlns:dc="http://purl.org/dc/elements/1.1/"
                       xmlns:dcterms="http://purl.org/dc/terms/"
                       xmlns:sec="http://jvn.jp/rss/mod_sec/3.0/">
        <title>テスト</title>
        <link>https://example.com</link>
        <dc:identifier>JVN#12345678</dc:identifier>
        <dc:date>2026-06-18T00:00:00+09:00</dc:date>
        <dcterms:modified>2026-06-18T00:00:00+09:00</dcterms:modified>
    </item>"""
    item = ET.fromstring(xml_str)
    result = _parse_item(item)
    assert result is None


def test_parse_item_valid():
    """正常な JVNDB アイテムがパースされること。"""
    import defusedxml.ElementTree as ET

    from app.cron_jvn import _parse_item

    xml_str = """<item xmlns:dc="http://purl.org/dc/elements/1.1/"
                       xmlns:dcterms="http://purl.org/dc/terms/"
                       xmlns:sec="http://jvn.jp/rss/mod_sec/3.0/">
        <title>テスト脆弱性タイトル</title>
        <link>https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000001.html</link>
        <description>概要テキスト</description>
        <dc:identifier>JVNDB-2026-000001</dc:identifier>
        <dc:date>2026-06-18T00:00:00+09:00</dc:date>
        <dcterms:modified>2026-06-18T00:00:00+09:00</dcterms:modified>
        <sec:cvss score="9.8" vector="AV:N/AC:L" severity="高"/>
        <sec:references type="CVE" id="CVE-2026-12345"/>
        <sec:affected vendor="TestVendor" name="TestProduct" cpe="cpe:/a:test:product"/>
    </item>"""
    item = ET.fromstring(xml_str)
    result = _parse_item(item)
    assert result is not None
    assert result["jvndb_id"] == "JVNDB-2026-000001"
    assert result["severity"] == "High"
    assert result["cvss_score"] == 9.8
    assert "CVE-2026-12345" in result["cve_ids"]
    assert len(result["affected_products"]) == 1


def test_fetch_page_returns_none_on_http_error(monkeypatch):
    """HTTP エラー時は None を返すこと。"""
    import httpx

    from app.cron_jvn import _fetch_page

    def mock_get(*args, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr("app.cron_jvn.httpx.Client", lambda **kw: MagicMock(
        __enter__=lambda s: MagicMock(get=mock_get),
        __exit__=lambda s, *a: None,
    ))

    result = _fetch_page("2026-06-01", 1)
    assert result is None


def test_fetch_all_entries_returns_empty_on_none(monkeypatch):
    """_fetch_page が None を返した場合は空リストになること。"""
    monkeypatch.setattr("app.cron_jvn._fetch_page", lambda *a: None)

    from app.cron_jvn import _fetch_all_entries

    result = _fetch_all_entries("2026-06-01")
    assert result == []
