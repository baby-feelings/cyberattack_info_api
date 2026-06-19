"""MyJVN API クローラー。
JVN DB (jvndb.jvn.jp) から脆弱性情報を取得し、jvn_vulnerabilities テーブルに Upsert する。
MyJVN REST API の getVulnOverviewList メソッドを使用し、直近 JVN_DAYS 日分を取得する。
"""
import logging
import re
import time
import xml.etree.ElementTree as stdlib_ET  # Element 型のみ使用（defusedxml は型を非公開）
from datetime import datetime, timedelta, timezone

import defusedxml.ElementTree as defused_ET  # XXE / billion-laughs 攻撃防止
import httpx
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.crawler_log import now_utc, write_crawler_log
from app.database import SessionLocal
from app.models import JvnVulnerability
from app.notifications import notify_jvn_crawl_error, notify_jvn_new_vulnerabilities

logger = logging.getLogger(__name__)

# MyJVN REST API ベース URL
_MYJVN_BASE_URL = "https://jvndb.jvn.jp/myjvn"

# 1回のリクエストで取得できる最大件数（MyJVN API の上限）
_MAX_COUNT_ITEM = 50

# 定期コミット間隔（Neon 無料プランの長時間トランザクションタイムアウト対策）
_COMMIT_EVERY = 50

# XML 名前空間マッピング
_NS = {
    "rss": "http://purl.org/rss/1.0/",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "sec": "http://jvn.jp/rss/mod_sec/3.0/",
    "status": "http://jvndb.jvn.jp/myjvn/Status",
}


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


def _fetch_page(cutoff_date: str, start_item: int) -> stdlib_ET.Element | None:
    """MyJVN API の getVulnOverviewList を 1 ページ分取得する。

    Args:
        cutoff_date: dateLastModified パラメータ（YYYY-MM-DD 形式）
        start_item:  取得開始位置（1始まり）

    Returns:
        XML の root Element、失敗時は None
    """
    params = {
        "method": "getVulnOverviewList",
        "feed": "hnd",
        "startItem": str(start_item),
        "maxCountItem": str(_MAX_COUNT_ITEM),
        "dateLastModified": cutoff_date,
    }
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(_MYJVN_BASE_URL, params=params)
            resp.raise_for_status()
        return defused_ET.fromstring(resp.text)
    except (httpx.HTTPError, stdlib_ET.ParseError) as exc:
        logger.error("MyJVN API fetch failed (start=%d): %s", start_item, exc)
        return None


def _parse_item(item: stdlib_ET.Element) -> dict | None:
    """RSS <item> 要素から JVN 脆弱性データを抽出する。

    Returns:
        dict 形式のデータ、必須フィールド欠損時は None
    """
    # JVNDB ID（例: JVNDB-2026-020171）— MyJVN API は sec:identifier を使用
    identifier = item.findtext("sec:identifier", namespaces=_NS) or ""
    if not identifier.startswith("JVNDB-"):
        # JVN ID（JVN#xxxxxxxx 形式）は対象外
        return None

    # RSS 1.0 の title/link は既定名前空間（rss:）またはプレフィックスなしの両方に対応
    title = (
        item.findtext("rss:title", namespaces=_NS)
        or item.findtext("title", namespaces=_NS)
        or ""
    )
    link = (
        item.findtext("rss:link", namespaces=_NS)
        or item.findtext("link", namespaces=_NS)
        or ""
    )
    description = _strip_html(
        item.findtext("rss:description", namespaces=_NS)
        or item.findtext("description", namespaces=_NS)
        or ""
    )
    date_published = _parse_datetime(item.findtext("dc:date", namespaces=_NS))
    date_last_modified = _parse_datetime(item.findtext("dcterms:modified", namespaces=_NS))

    if not identifier or not title or not link:
        return None
    if date_published is None or date_last_modified is None:
        return None

    # CVSSv2 情報
    cvss2 = item.find("sec:cvss", namespaces=_NS)
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str | None = None
    if cvss2 is not None:
        score_str = cvss2.get("score")
        if score_str:
            try:
                cvss_score = float(score_str)
            except ValueError:
                pass
        cvss_vector = cvss2.get("vector") or None
        severity_raw = cvss2.get("severity") or ""
        # 重要度を正規化（高/中/低 → High/Medium/Low）
        severity_map = {"高": "High", "中": "Medium", "低": "Low",
                        "High": "High", "Medium": "Medium", "Low": "Low"}
        severity = severity_map.get(severity_raw)

    # 関連 CVE ID を収集（sec:references の source="CVE" 要素から）
    cve_ids: list[str] = []
    for ref in item.findall("sec:references", namespaces=_NS):
        if ref.get("source") == "CVE":
            ref_id = ref.get("id", "")
            if ref_id.startswith("CVE-"):
                cve_ids.append(ref_id)

    # 影響製品（sec:cpe 要素の vendor/product 属性と CPE テキストから）
    affected_products: list[dict] = []
    for cpe_elem in item.findall("sec:cpe", namespaces=_NS):
        vendor = cpe_elem.get("vendor", "")
        product_name = cpe_elem.get("product", "")
        cpe = cpe_elem.text or ""
        if vendor or product_name:
            affected_products.append({"vendor": vendor, "product": product_name, "cpe": cpe})

    return {
        "jvndb_id": identifier,
        "title": title,
        "overview": description,
        "cve_ids": cve_ids,
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "affected_products": affected_products,
        "references": [],  # overview リストには詳細参考リンクが含まれないため空
        "jvn_url": link,
        "date_published": date_published,
        "date_last_modified": date_last_modified,
    }


def _fetch_all_entries(cutoff_date: str) -> list[dict]:
    """全ページを取得して脆弱性データのリストを返す。

    Args:
        cutoff_date: dateLastModified フィルターの基準日（YYYY-MM-DD 形式）

    Returns:
        脆弱性データの dict リスト
    """
    entries: list[dict] = []
    start_item = 1

    # 1ページ目を取得して totalRes（総件数）を確認
    root: stdlib_ET.Element | None = _fetch_page(cutoff_date, start_item)
    if root is None:
        return entries

    # Status 要素から総件数を取得
    status_elem = root.find("status:Status", namespaces=_NS)
    total_res = 0
    if status_elem is not None:
        try:
            total_res = int(status_elem.get("totalRes", "0"))
        except (ValueError, TypeError):
            total_res = 0

    logger.info("MyJVN totalRes=%d (cutoff=%s)", total_res, cutoff_date)

    # 全ページをループして item を収集
    while True:
        if root is None:
            break
        for item in root.findall("rss:item", namespaces=_NS):
            parsed = _parse_item(item)
            if parsed:
                entries.append(parsed)

        # 次ページがあるか確認
        start_item += _MAX_COUNT_ITEM
        if start_item > total_res:
            break

        # レートリミット対策で少し待機
        time.sleep(0.5)
        root = _fetch_page(cutoff_date, start_item)

    logger.info("Fetched %d JVN entries (cutoff=%s)", len(entries), cutoff_date)
    return entries


def _apply_update(existing: JvnVulnerability, data: dict) -> bool:
    """既存レコードに新しいデータを適用し、変更があれば True を返す。"""
    changed = existing.date_last_modified != data["date_last_modified"]
    existing.title = data["title"]
    existing.overview = data["overview"]
    existing.cve_ids = data["cve_ids"]
    existing.severity = data["severity"]
    existing.cvss_score = data["cvss_score"]
    existing.cvss_vector = data["cvss_vector"]
    existing.affected_products = data["affected_products"]
    existing.references = data["references"]
    existing.jvn_url = data["jvn_url"]
    existing.date_published = data["date_published"]
    existing.date_last_modified = data["date_last_modified"]
    return changed


def _upsert_jvn(db: Session, entries: list[dict]) -> tuple[int, int]:
    """JVN エントリを jvn_vulnerabilities テーブルに Upsert する。

    Args:
        db:      SQLAlchemy セッション
        entries: _fetch_all_entries が返した dict リスト

    Returns:
        (inserted, updated) のタプル
    """
    inserted = 0
    updated = 0
    count = 0

    # リスト内の jvndb_id 重複を除去（最後の要素を優先）
    deduped: dict[str, dict] = {}
    for entry in entries:
        deduped[entry["jvndb_id"]] = entry

    for jvndb_id, data in deduped.items():
        existing = db.query(JvnVulnerability).filter(
            JvnVulnerability.jvndb_id == jvndb_id
        ).first()

        if existing is None:
            try:
                # 新規挿入（flush で即座にユニーク制約を検査）
                record = JvnVulnerability(**data)
                db.add(record)
                db.flush()
                inserted += 1
            except IntegrityError:
                # 並行プロセスが先に INSERT した場合は UPDATE に切り替える
                db.rollback()
                existing = db.query(JvnVulnerability).filter(
                    JvnVulnerability.jvndb_id == jvndb_id
                ).first()
                if existing and _apply_update(existing, data):
                    updated += 1
        else:
            # 更新（date_last_modified が変化している場合のみカウント）
            if _apply_update(existing, data):
                updated += 1

        count += 1
        # 定期コミット（Neon タイムアウト対策）
        if count % _COMMIT_EVERY == 0:
            db.commit()

    db.commit()
    return inserted, updated


def fetch_and_store_jvn() -> tuple[int, int]:
    """MyJVN API から脆弱性情報を取得して DB に保存する。

    Returns:
        (inserted, updated) のタプル
    """
    started_at = now_utc()
    logger.info("JVN crawler started")

    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.JVN_DAYS)
    cutoff_date = cutoff.strftime("%Y-%m-%d")

    db = SessionLocal()
    try:
        entries = _fetch_all_entries(cutoff_date)
        inserted, updated = _upsert_jvn(db, entries)

        finished_at = now_utc()
        duration = (finished_at - started_at).total_seconds()
        logger.info(
            "JVN crawler done: inserted=%d, updated=%d, duration=%.1fs",
            inserted, updated, duration,
        )

        write_crawler_log(
            crawler_type="JVN",
            status="success",
            started_at=started_at,
            finished_at=finished_at,
            inserted=inserted,
            updated=updated,
        )
        notify_jvn_new_vulnerabilities(inserted=inserted, updated=updated)
        return inserted, updated

    except Exception as exc:
        finished_at = now_utc()
        logger.error("JVN crawler failed: %s", exc, exc_info=True)
        write_crawler_log(
            crawler_type="JVN",
            status="error",
            started_at=started_at,
            finished_at=finished_at,
            error_message=str(exc),
        )
        notify_jvn_crawl_error(str(exc))
        raise
    finally:
        db.close()
