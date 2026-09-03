"""MyJVN API（RDF/RSS 1.0）レスポンスのパース処理。

XML の <item> 要素から JVN 脆弱性データを抽出する純粋関数群。
HTTP 通信・DB Upsert・保持期間管理は app.jvn.crawler が担当する。
"""
import re
import xml.etree.ElementTree as stdlib_ET  # Element 型のみ使用（defusedxml は型を非公開）
from datetime import datetime

# XML 名前空間マッピング
NS = {
    "rss": "http://purl.org/rss/1.0/",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "sec": "http://jvn.jp/rss/mod_sec/3.0/",
    "status": "http://jvndb.jvn.jp/myjvn/Status",
}

# CVSS の重要度表記を正規化する（高/中/低 → High/Medium/Low）
_SEVERITY_MAP = {"高": "High", "中": "Medium", "低": "Low",
                 "High": "High", "Medium": "Medium", "Low": "Low"}


def _strip_html(text: str) -> str:
    """HTML タグを除去してプレーンテキストを返す。"""
    return re.sub(r"<[^>]+>", "", text).strip()


def _parse_datetime(value: str | None) -> datetime | None:
    """ISO 8601 日付文字列を timezone-aware datetime に変換する。"""
    if not value:
        return None
    try:
        # +09:00 等のタイムゾーン付き文字列を処理
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def _parse_core_fields(item: stdlib_ET.Element) -> dict | None:
    """<item> 要素から識別子・タイトル・リンク・概要・日付を抽出する。

    Returns:
        dict 形式のデータ、必須フィールド欠損時は None
    """
    # JVNDB ID（例: JVNDB-2026-020171）— MyJVN API は sec:identifier を使用
    identifier = item.findtext("sec:identifier", namespaces=NS) or ""
    if not identifier.startswith("JVNDB-"):
        # JVN ID（JVN#xxxxxxxx 形式）は対象外
        return None

    # RSS 1.0 の title/link は既定名前空間（rss:）またはプレフィックスなしの両方に対応
    title = (
        item.findtext("rss:title", namespaces=NS)
        or item.findtext("title", namespaces=NS)
        or ""
    )
    link = (
        item.findtext("rss:link", namespaces=NS)
        or item.findtext("link", namespaces=NS)
        or ""
    )
    description = _strip_html(
        item.findtext("rss:description", namespaces=NS)
        or item.findtext("description", namespaces=NS)
        or ""
    )
    date_published = _parse_datetime(item.findtext("dc:date", namespaces=NS))
    date_last_modified = _parse_datetime(item.findtext("dcterms:modified", namespaces=NS))

    if not identifier or not title or not link:
        return None
    if date_published is None or date_last_modified is None:
        return None

    return {
        "jvndb_id": identifier,
        "title": title,
        "overview": description,
        "jvn_url": link,
        "date_published": date_published,
        "date_last_modified": date_last_modified,
    }


def _parse_cvss(item: stdlib_ET.Element) -> tuple[float | None, str | None, str | None]:
    """<item> 要素から CVSSv2 情報（スコア・ベクター・重要度）を抽出する。"""
    cvss2 = item.find("sec:cvss", namespaces=NS)
    if cvss2 is None:
        return None, None, None

    cvss_score: float | None = None
    score_str = cvss2.get("score")
    if score_str:
        try:
            cvss_score = float(score_str)
        except ValueError:
            pass

    cvss_vector = cvss2.get("vector") or None
    severity = _SEVERITY_MAP.get(cvss2.get("severity") or "")
    return cvss_score, cvss_vector, severity


def _parse_cve_ids(item: stdlib_ET.Element) -> list[str]:
    """<item> 要素から関連 CVE ID を収集する（sec:references の source="CVE" 要素から）。"""
    cve_ids: list[str] = []
    for ref in item.findall("sec:references", namespaces=NS):
        if ref.get("source") == "CVE":
            ref_id = ref.get("id", "")
            if ref_id.startswith("CVE-"):
                cve_ids.append(ref_id)
    return cve_ids


def _parse_affected_products(item: stdlib_ET.Element) -> list[dict]:
    """<item> 要素から影響製品一覧を抽出する。

    sec:cpe 要素の vendor/product 属性と CPE テキストから構築する。
    """
    affected_products: list[dict] = []
    for cpe_elem in item.findall("sec:cpe", namespaces=NS):
        vendor = cpe_elem.get("vendor", "")
        product_name = cpe_elem.get("product", "")
        cpe = cpe_elem.text or ""
        if vendor or product_name:
            affected_products.append({"vendor": vendor, "product": product_name, "cpe": cpe})
    return affected_products


def parse_item(item: stdlib_ET.Element) -> dict | None:
    """RSS <item> 要素から JVN 脆弱性データを抽出する。

    Returns:
        dict 形式のデータ、必須フィールド欠損時は None
    """
    core = _parse_core_fields(item)
    if core is None:
        return None

    cvss_score, cvss_vector, severity = _parse_cvss(item)

    return {
        **core,
        "cve_ids": _parse_cve_ids(item),
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "affected_products": _parse_affected_products(item),
        "references": [],  # overview リストには詳細参考リンクが含まれないため空
    }
