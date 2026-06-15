"""OSV (Open Source Vulnerabilities) クローラーモジュール。

Google Cloud Storage から各エコシステムの脆弱性 zip を取得し、
直近 OSV_DAYS 日以内に更新されたエントリを DB に Upsert する。
APScheduler から毎週呼び出される。
"""
import io
import json
import logging
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.models import OsvVulnerability

logger = logging.getLogger(__name__)

# 取得対象のエコシステム（言語パッケージマネージャー中心）
TARGET_ECOSYSTEMS = [
    "PyPI",
    "npm",
    "Go",
    "Maven",
    "RubyGems",
    "NuGet",
    "crates.io",
    "Packagist",
    "Hex",
]

# OSV GCS バケット基底 URL
OSV_GCS_BASE = "https://osv-vulnerabilities.storage.googleapis.com"


def _fetch_ecosystem_zip(ecosystem: str) -> bytes:
    """GCS から指定エコシステムの all.zip をダウンロードして返す。

    Args:
        ecosystem: エコシステム名（例: PyPI, npm）

    Returns:
        zip ファイルのバイト列

    Raises:
        httpx.HTTPError: ダウンロード失敗時
    """
    url = f"{OSV_GCS_BASE}/{ecosystem}/all.zip"
    logger.info("Downloading OSV zip: %s", url)
    with httpx.Client(timeout=120.0, follow_redirects=True) as client:
        response = client.get(url)
        response.raise_for_status()
    size_mb = len(response.content) / 1024 / 1024
    logger.info("Downloaded %s: %.1f MB", ecosystem, size_mb)
    return response.content


def _parse_severity(vuln: dict[str, Any]) -> tuple[str | None, float | None]:
    """OSV エントリから重要度ラベルと CVSS スコアを抽出する。

    優先順位:
    1. database_specific.severity（GitHub Advisory Database が付与する文字列）
    2. database_specific.cvss.score（数値スコア）
    3. severity[].score が数値の場合（直接スコアが入っている場合）

    Returns:
        (severity_label, cvss_score) のタプル
    """
    db_specific = vuln.get("database_specific", {}) or {}

    # 1. database_specific.severity（CRITICAL/HIGH/MEDIUM/LOW 文字列）
    sev_str = (db_specific.get("severity") or "").upper()
    if sev_str in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        # database_specific.cvss.score から数値スコアを補完
        cvss_score: float | None = None
        try:
            raw = (db_specific.get("cvss") or {}).get("score")
            if raw is not None:
                cvss_score = float(raw)
        except (TypeError, ValueError):
            pass
        return sev_str, cvss_score

    # 2. severity 配列に数値スコアが直接格納されている場合
    for sev in vuln.get("severity", []):
        try:
            score = float(sev.get("score", ""))
            if score >= 9.0:
                return "CRITICAL", score
            elif score >= 7.0:
                return "HIGH", score
            elif score >= 4.0:
                return "MEDIUM", score
            else:
                return "LOW", score
        except (TypeError, ValueError):
            pass

    return None, None


def _extract_fixed_versions(affected: dict[str, Any]) -> list[str]:
    """affected エントリの ranges から修正済みバージョン（fixed イベント）を抽出する。"""
    fixed: list[str] = []
    for rng in affected.get("ranges", []):
        for event in rng.get("events", []):
            if "fixed" in event:
                fixed.append(event["fixed"])
    return fixed


def _build_records(
    vuln: dict[str, Any], modified: datetime
) -> list[dict[str, Any]]:
    """OSV エントリを DB レコード辞書のリストに変換する。

    1つの脆弱性が複数パッケージに影響する場合は 1 レコード/パッケージ を生成する。

    Args:
        vuln: OSV vulnerability JSON オブジェクト
        modified: 更新日時（timezone-aware）

    Returns:
        DB レコード辞書のリスト
    """
    severity, cvss_score = _parse_severity(vuln)

    # 公開日時をパース（失敗時は modified で代替）
    published_str = vuln.get("published", "")
    try:
        published = datetime.fromisoformat(
            published_str.replace("Z", "+00:00")
        )
    except (ValueError, AttributeError):
        published = modified

    osv_id = vuln.get("id", "")
    aliases = [a for a in (vuln.get("aliases") or []) if a]
    # 参考リンクは最大 5 件に制限してストレージを節約
    refs = [r["url"] for r in (vuln.get("references") or []) if r.get("url")][:5]
    summary = (vuln.get("summary") or "").strip()
    details = (vuln.get("details") or None)

    records: list[dict[str, Any]] = []

    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {}) or {}
        pkg_name = (pkg.get("name") or "").strip()
        pkg_eco = (pkg.get("ecosystem") or "").strip()
        if not pkg_name or not pkg_eco:
            continue

        # 影響バージョンは最大 30 件に制限
        affected_versions = (affected.get("versions") or [])[:30]
        fixed_versions = _extract_fixed_versions(affected)

        records.append(
            {
                "osv_id": osv_id,
                "ecosystem": pkg_eco,
                "package_name": pkg_name,
                "aliases": aliases,
                "summary": summary,
                "details": details,
                "severity": severity,
                "cvss_score": cvss_score,
                "affected_versions": affected_versions,
                "fixed_versions": fixed_versions,
                "references": refs,
                "published": published,
                "modified": modified,
            }
        )

    return records


def _process_zip(
    ecosystem: str, zip_bytes: bytes, cutoff: datetime
) -> list[dict[str, Any]]:
    """zip バイト列を展開し、cutoff 以降に更新された脆弱性のレコード一覧を返す。

    Args:
        ecosystem: エコシステム名（ログ用）
        zip_bytes: GCS からダウンロードした zip のバイト列
        cutoff: この日時より古い modified は除外する

    Returns:
        DB に挿入する dict のリスト
    """
    all_records: list[dict[str, Any]] = []

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                data = json.loads(zf.read(name))
            except (json.JSONDecodeError, KeyError):
                continue

            # modified をパースしてフィルタリング
            modified_str = data.get("modified", "")
            if not modified_str:
                continue
            try:
                modified = datetime.fromisoformat(
                    modified_str.replace("Z", "+00:00")
                )
            except ValueError:
                continue

            if modified < cutoff:
                continue  # 古いエントリはスキップ

            all_records.extend(_build_records(data, modified))

    logger.info(
        "Processed %s: %d records (modified >= %s)",
        ecosystem,
        len(all_records),
        cutoff.date(),
    )
    return all_records


def _upsert_osv_records(
    db: Session, records: list[dict[str, Any]]
) -> tuple[int, int]:
    """OSV レコードを DB に Upsert する。

    (osv_id, ecosystem, package_name) をキーに INSERT または UPDATE する。
    modified が変化していない場合は UPDATE をスキップしてパフォーマンスを最適化する。

    Returns:
        (inserted_count, updated_count) のタプル
    """
    inserted = 0
    updated = 0

    for rec in records:
        existing = (
            db.query(OsvVulnerability)
            .filter(
                OsvVulnerability.osv_id == rec["osv_id"],
                OsvVulnerability.ecosystem == rec["ecosystem"],
                OsvVulnerability.package_name == rec["package_name"],
            )
            .first()
        )

        if existing is None:
            db.add(OsvVulnerability(**rec))
            inserted += 1
        elif existing.modified != rec["modified"]:
            # modified が更新されている場合のみ上書き
            for key, value in rec.items():
                setattr(existing, key, value)
            updated += 1

    db.commit()
    return inserted, updated


def fetch_and_store_osv() -> None:
    """OSV クローラーのメインエントリポイント。

    全対象エコシステムを順次ダウンロードし、直近 OSV_DAYS 日分を DB に保存する。
    1エコシステムが失敗しても他のエコシステムの処理を継続する。
    APScheduler から定期呼び出しされる。
    """
    logger.info("=== OSV crawler started ===")
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.OSV_DAYS)
    total_inserted = 0
    total_updated = 0

    db: Session = SessionLocal()
    try:
        for ecosystem in TARGET_ECOSYSTEMS:
            try:
                zip_bytes = _fetch_ecosystem_zip(ecosystem)
                records = _process_zip(ecosystem, zip_bytes, cutoff)
                ins, upd = _upsert_osv_records(db, records)
                total_inserted += ins
                total_updated += upd
                logger.info(
                    "OSV [%s] done: inserted=%d updated=%d",
                    ecosystem, ins, upd,
                )
            except httpx.HTTPError as exc:
                # 1エコシステムのネットワークエラーは継続
                logger.error(
                    "HTTP error for ecosystem %s: %s", ecosystem, exc
                )
            except Exception as exc:
                logger.error(
                    "Unexpected error for ecosystem %s: %s",
                    ecosystem, exc, exc_info=True,
                )
    finally:
        db.close()

    logger.info(
        "=== OSV crawler completed: inserted=%d, updated=%d ===",
        total_inserted, total_updated,
    )
