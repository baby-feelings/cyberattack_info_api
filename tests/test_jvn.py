"""JVN API エンドポイントおよびクローラーユニットテスト。

外部 MyJVN API への HTTP 通信はモックし、ロジックのみを検証する。
"""
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.exc import IntegrityError

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
    """JVNDB- で始まらない sec:identifier はスキップされること。"""
    import defusedxml.ElementTree as ET

    from app.cron_jvn import _parse_item

    # 実際の MyJVN API と同じ構造: sec:identifier が JVN# 形式
    xml_str = """<item xmlns:dc="http://purl.org/dc/elements/1.1/"
                       xmlns:dcterms="http://purl.org/dc/terms/"
                       xmlns:sec="http://jvn.jp/rss/mod_sec/3.0/">
        <title>テスト</title>
        <link>https://example.com</link>
        <sec:identifier>JVN#12345678</sec:identifier>
        <dc:date>2026-06-18T00:00:00+09:00</dc:date>
        <dcterms:modified>2026-06-18T00:00:00+09:00</dcterms:modified>
    </item>"""
    item = ET.fromstring(xml_str)
    result = _parse_item(item)
    assert result is None


def test_parse_item_valid():
    """正常な JVNDB アイテムが実際の MyJVN API 構造でパースされること。"""
    import defusedxml.ElementTree as ET

    from app.cron_jvn import _parse_item

    # 実際の MyJVN API レスポンスと同じ要素構造を使用
    xml_str = """<item xmlns:dc="http://purl.org/dc/elements/1.1/"
                       xmlns:dcterms="http://purl.org/dc/terms/"
                       xmlns:sec="http://jvn.jp/rss/mod_sec/3.0/">
        <title>テスト脆弱性タイトル</title>
        <link>https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000001.html</link>
        <description>概要テキスト</description>
        <sec:identifier>JVNDB-2026-000001</sec:identifier>
        <dc:date>2026-06-18T00:00:00+09:00</dc:date>
        <dcterms:modified>2026-06-18T00:00:00+09:00</dcterms:modified>
        <sec:cvss score="9.8" vector="AV:N/AC:L" severity="High" version="3.0" type="Base"/>
        <sec:references source="CVE" id="CVE-2026-12345">https://nvd.nist.gov/vuln/detail/CVE-2026-12345</sec:references>
        <sec:cpe version="2.2" vendor="TestVendor"
            product="TestProduct">cpe:/a:test:product</sec:cpe>
    </item>"""
    item = ET.fromstring(xml_str)
    result = _parse_item(item)
    assert result is not None
    assert result["jvndb_id"] == "JVNDB-2026-000001"
    assert result["severity"] == "High"
    assert result["cvss_score"] == 9.8
    assert "CVE-2026-12345" in result["cve_ids"]
    assert len(result["affected_products"]) == 1
    assert result["affected_products"][0]["product"] == "TestProduct"
    assert result["affected_products"][0]["cpe"] == "cpe:/a:test:product"


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


# ── _fetch_page 成功パス ─────────────────────────────────────────


def test_fetch_page_success(monkeypatch):
    """_fetch_page が正常レスポンスを XML Element として返すこと。"""
    from app.cron_jvn import _fetch_page

    xml_body = '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"></rdf:RDF>'

    mock_resp = MagicMock()
    mock_resp.text = xml_body
    mock_resp.raise_for_status = MagicMock()

    mock_client = MagicMock()
    mock_client.__enter__ = lambda s: MagicMock(get=lambda *a, **kw: mock_resp)
    mock_client.__exit__ = lambda s, *a: None

    monkeypatch.setattr("app.cron_jvn.httpx.Client", lambda **kw: mock_client)

    result = _fetch_page("2026-06-01", 1)
    assert result is not None
    assert result.tag.endswith("RDF")


# ── _parse_item エッジケース ─────────────────────────────────────


def test_parse_item_missing_title_returns_none():
    """title が空の場合は None を返すこと。"""
    import defusedxml.ElementTree as ET

    from app.cron_jvn import _parse_item

    xml_str = """<item xmlns:dc="http://purl.org/dc/elements/1.1/"
                       xmlns:dcterms="http://purl.org/dc/terms/"
                       xmlns:sec="http://jvn.jp/rss/mod_sec/3.0/">
        <link>https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000001.html</link>
        <sec:identifier>JVNDB-2026-000001</sec:identifier>
        <dc:date>2026-06-18T00:00:00+09:00</dc:date>
        <dcterms:modified>2026-06-18T00:00:00+09:00</dcterms:modified>
    </item>"""
    item = ET.fromstring(xml_str)
    assert _parse_item(item) is None


def test_parse_item_missing_dates_returns_none():
    """日付が欠損している場合は None を返すこと。"""
    import defusedxml.ElementTree as ET

    from app.cron_jvn import _parse_item

    xml_str = """<item xmlns:dc="http://purl.org/dc/elements/1.1/"
                       xmlns:dcterms="http://purl.org/dc/terms/"
                       xmlns:sec="http://jvn.jp/rss/mod_sec/3.0/">
        <title>テスト脆弱性</title>
        <link>https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000001.html</link>
        <sec:identifier>JVNDB-2026-000001</sec:identifier>
    </item>"""
    item = ET.fromstring(xml_str)
    assert _parse_item(item) is None


def test_parse_item_invalid_cvss_score():
    """CVSS score が数値でない場合はスコアが None になること。"""
    import defusedxml.ElementTree as ET

    from app.cron_jvn import _parse_item

    xml_str = """<item xmlns:dc="http://purl.org/dc/elements/1.1/"
                       xmlns:dcterms="http://purl.org/dc/terms/"
                       xmlns:sec="http://jvn.jp/rss/mod_sec/3.0/">
        <title>テスト脆弱性</title>
        <link>https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000001.html</link>
        <sec:identifier>JVNDB-2026-000001</sec:identifier>
        <dc:date>2026-06-18T00:00:00+09:00</dc:date>
        <dcterms:modified>2026-06-18T00:00:00+09:00</dcterms:modified>
        <sec:cvss score="N/A" vector="AV:N" severity="High"/>
    </item>"""
    item = ET.fromstring(xml_str)
    result = _parse_item(item)
    assert result is not None
    assert result["cvss_score"] is None
    assert result["cvss_vector"] == "AV:N"


# ── _fetch_all_entries ページングテスト ───────────────────────────


def test_fetch_all_entries_with_items(monkeypatch):
    """Status 要素付き RDF/RSS から item が正しくパースされること。"""
    import defusedxml.ElementTree as ET

    from app.cron_jvn import _fetch_all_entries

    rdf_xml = """<rdf:RDF
        xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
        xmlns="http://purl.org/rss/1.0/"
        xmlns:dc="http://purl.org/dc/elements/1.1/"
        xmlns:dcterms="http://purl.org/dc/terms/"
        xmlns:sec="http://jvn.jp/rss/mod_sec/3.0/"
        xmlns:status="http://jvndb.jvn.jp/myjvn/Status">
        <status:Status totalRes="1" />
        <item>
            <title>Test Vuln</title>
            <link>https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000001.html</link>
            <description>概要</description>
            <sec:identifier>JVNDB-2026-000001</sec:identifier>
            <dc:date>2026-06-18T00:00:00+09:00</dc:date>
            <dcterms:modified>2026-06-18T00:00:00+09:00</dcterms:modified>
        </item>
    </rdf:RDF>"""
    root = ET.fromstring(rdf_xml)
    monkeypatch.setattr("app.cron_jvn._fetch_page", lambda *a: root)

    result = _fetch_all_entries("2026-06-01")
    assert len(result) == 1
    assert result[0]["jvndb_id"] == "JVNDB-2026-000001"


def test_fetch_all_entries_pagination(monkeypatch):
    """totalRes > _MAX_COUNT_ITEM のとき複数ページを取得すること。"""
    import defusedxml.ElementTree as ET

    from app.cron_jvn import _fetch_all_entries

    # totalRes=51 で 2 ページ必要な状態をシミュレーション
    page1_xml = """<rdf:RDF
        xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
        xmlns="http://purl.org/rss/1.0/"
        xmlns:dc="http://purl.org/dc/elements/1.1/"
        xmlns:dcterms="http://purl.org/dc/terms/"
        xmlns:sec="http://jvn.jp/rss/mod_sec/3.0/"
        xmlns:status="http://jvndb.jvn.jp/myjvn/Status">
        <status:Status totalRes="51" />
        <item>
            <title>Page1 Vuln</title>
            <link>https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000001.html</link>
            <sec:identifier>JVNDB-2026-000001</sec:identifier>
            <dc:date>2026-06-18T00:00:00+09:00</dc:date>
            <dcterms:modified>2026-06-18T00:00:00+09:00</dcterms:modified>
        </item>
    </rdf:RDF>"""
    page2_xml = """<rdf:RDF
        xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
        xmlns="http://purl.org/rss/1.0/"
        xmlns:dc="http://purl.org/dc/elements/1.1/"
        xmlns:dcterms="http://purl.org/dc/terms/"
        xmlns:sec="http://jvn.jp/rss/mod_sec/3.0/"
        xmlns:status="http://jvndb.jvn.jp/myjvn/Status">
        <status:Status totalRes="51" />
        <item>
            <title>Page2 Vuln</title>
            <link>https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000002.html</link>
            <sec:identifier>JVNDB-2026-000002</sec:identifier>
            <dc:date>2026-06-18T00:00:00+09:00</dc:date>
            <dcterms:modified>2026-06-18T00:00:00+09:00</dcterms:modified>
        </item>
    </rdf:RDF>"""
    pages = [ET.fromstring(page1_xml), ET.fromstring(page2_xml)]
    call_count = [0]

    def mock_fetch_page(cutoff_date, start_item):
        idx = call_count[0]
        call_count[0] += 1
        return pages[idx] if idx < len(pages) else None

    monkeypatch.setattr("app.cron_jvn._fetch_page", mock_fetch_page)
    monkeypatch.setattr("app.cron_jvn.time.sleep", lambda s: None)

    result = _fetch_all_entries("2026-06-01")
    assert len(result) == 2
    assert call_count[0] == 2


def test_fetch_all_entries_invalid_total_res(monkeypatch):
    """totalRes が不正な値のとき 0 として扱い、1 ページ目のみ処理すること。"""
    import defusedxml.ElementTree as ET

    from app.cron_jvn import _fetch_all_entries

    rdf_xml = """<rdf:RDF
        xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
        xmlns="http://purl.org/rss/1.0/"
        xmlns:dc="http://purl.org/dc/elements/1.1/"
        xmlns:dcterms="http://purl.org/dc/terms/"
        xmlns:sec="http://jvn.jp/rss/mod_sec/3.0/"
        xmlns:status="http://jvndb.jvn.jp/myjvn/Status">
        <status:Status totalRes="invalid" />
        <item>
            <title>Test</title>
            <link>https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000001.html</link>
            <sec:identifier>JVNDB-2026-000001</sec:identifier>
            <dc:date>2026-06-18T00:00:00+09:00</dc:date>
            <dcterms:modified>2026-06-18T00:00:00+09:00</dcterms:modified>
        </item>
    </rdf:RDF>"""
    root = ET.fromstring(rdf_xml)
    monkeypatch.setattr("app.cron_jvn._fetch_page", lambda *a: root)

    result = _fetch_all_entries("2026-06-01")
    # totalRes=0 なので 1 ページ目の item は処理される（while ループ内）が
    # 次ページには進まない
    assert len(result) == 1


def test_fetch_all_entries_second_page_returns_none(monkeypatch):
    """2 ページ目が None を返した場合はそこでループ終了すること。"""
    import defusedxml.ElementTree as ET

    from app.cron_jvn import _fetch_all_entries

    rdf_xml = """<rdf:RDF
        xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
        xmlns="http://purl.org/rss/1.0/"
        xmlns:dc="http://purl.org/dc/elements/1.1/"
        xmlns:dcterms="http://purl.org/dc/terms/"
        xmlns:sec="http://jvn.jp/rss/mod_sec/3.0/"
        xmlns:status="http://jvndb.jvn.jp/myjvn/Status">
        <status:Status totalRes="100" />
        <item>
            <title>Test</title>
            <link>https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-000001.html</link>
            <sec:identifier>JVNDB-2026-000001</sec:identifier>
            <dc:date>2026-06-18T00:00:00+09:00</dc:date>
            <dcterms:modified>2026-06-18T00:00:00+09:00</dcterms:modified>
        </item>
    </rdf:RDF>"""
    root = ET.fromstring(rdf_xml)
    call_count = [0]

    def mock_fetch_page(cutoff_date, start_item):
        call_count[0] += 1
        # 1 ページ目のみ返し、2 ページ目は None
        return root if call_count[0] == 1 else None

    monkeypatch.setattr("app.cron_jvn._fetch_page", mock_fetch_page)
    monkeypatch.setattr("app.cron_jvn.time.sleep", lambda s: None)

    result = _fetch_all_entries("2026-06-01")
    assert len(result) == 1
    assert call_count[0] == 2


# ── _upsert_jvn エッジケース ─────────────────────────────────────


def test_upsert_jvn_integrity_error_fallback(db_session):
    """IntegrityError 発生時にフォールバックで UPDATE されること。"""
    from app.cron_jvn import _upsert_jvn

    # まず既存レコードを入れておく
    db_session.add(_make_jvn(jvndb_id="JVNDB-2026-999010"))
    db_session.commit()

    new_modified = datetime(2026, 6, 19, 0, 0, 0, tzinfo=timezone.utc)
    entry = {
        "jvndb_id": "JVNDB-2026-999010",
        "title": "更新後タイトル",
        "overview": "更新概要",
        "cve_ids": [],
        "severity": "Medium",
        "cvss_score": 5.0,
        "cvss_vector": None,
        "affected_products": [],
        "references": [],
        "jvn_url": "https://jvndb.jvn.jp/",
        "date_published": _NOW,
        "date_last_modified": new_modified,
    }

    # flush で IntegrityError を発生させるモック DB
    real_query = db_session.query
    real_add = db_session.add
    real_commit = db_session.commit
    real_rollback = db_session.rollback
    first_query = [True]

    mock_db = MagicMock()
    mock_db.commit = real_commit
    mock_db.rollback = real_rollback

    def mock_query(*args, **kwargs):
        q = real_query(*args, **kwargs)
        if first_query[0]:
            first_query[0] = False
            # 1 回目の query は None を返し、新規挿入を試みさせる
            mock_filter = MagicMock()
            mock_filter.first.return_value = None
            return MagicMock(filter=lambda *fa, **fkw: mock_filter)
        return q

    mock_db.query = mock_query
    mock_db.add = real_add

    def raise_integrity(*a, **kw):
        raise IntegrityError("UNIQUE constraint failed", {}, Exception("dup"))

    mock_db.flush = raise_integrity

    inserted, updated = _upsert_jvn(mock_db, [entry])
    assert inserted == 0
    assert updated == 1

    # 実際の DB にも反映されていることを確認
    record = db_session.query(JvnVulnerability).filter_by(
        jvndb_id="JVNDB-2026-999010"
    ).first()
    assert record is not None
    assert record.title == "更新後タイトル"


def test_upsert_jvn_periodic_commit(db_session):
    """_COMMIT_EVERY 件ごとに定期コミットが行われること。"""
    from app.cron_jvn import _upsert_jvn

    entries = []
    for i in range(3):
        entries.append({
            "jvndb_id": f"JVNDB-2026-888{i:03d}",
            "title": f"定期コミットテスト {i}",
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
        })

    # _COMMIT_EVERY=1 にして毎件コミットをトリガー
    with patch("app.cron_jvn._COMMIT_EVERY", 1):
        inserted, updated = _upsert_jvn(db_session, entries)

    assert inserted == 3
    assert updated == 0
