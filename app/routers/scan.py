"""ライブラリ脆弱性スキャン API ルーター。

POST /api/scan                – パッケージリストを OSV + CISA KEV でスキャン
POST /api/scan/requirements   – requirements.txt 形式のテキストをスキャン
POST /api/scan/package-json   – package.json の dependencies をスキャン（npm）
GET  /api/scan/history        – スキャン履歴一覧
GET  /api/scan/history/{id}   – スキャン結果詳細
"""
import json
import logging
import re
from typing import Annotated

import httpx
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.auth import require_api_key
from app.database import get_db
from app.models import ScanResult, Vulnerability
from app.notifications import notify_scan_diff
from app.schemas import (
    PackageInput,
    ScanRequest,
    ScanResponse,
    ScanResultOut,
    VulnerabilityFinding,
)

logger = logging.getLogger(__name__)

# OSV（Open Source Vulnerabilities）API エンドポイント
OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT = 15.0

router = APIRouter(
    prefix="/api/scan",
    tags=["scan"],
    dependencies=[Depends(require_api_key)],
)


# ── 内部ヘルパー関数 ─────────────────────────────────────────────


def _extract_severity(vuln: dict) -> str | None:
    """OSV レスポンスから重要度ラベルを抽出する。
    database_specific.severity を優先し、なければ severity 配列の type を参照する。
    """
    # GitHub Advisory や NVD が付与する severity を優先使用
    db_specific = vuln.get("database_specific", {})
    severity = db_specific.get("severity", "")
    if severity:
        return severity.upper()

    # severity 配列から type=CVSS_V3 の評価を取得
    for sev in vuln.get("severity", []):
        sev_type = sev.get("type", "")
        if "CVSS" in sev_type:
            score_str = sev.get("score", "")
            if score_str:
                if "/AV:N/" in score_str and "/AC:L/" in score_str:
                    return "HIGH"
                return "MEDIUM"

    return None


def _extract_fixed_versions(vuln: dict, package_name: str) -> list[str]:
    """OSV の affected リストから修正済みバージョンを抽出する。"""
    fixed: list[str] = []
    for affected in vuln.get("affected", []):
        # パッケージ名が一致する affected エントリのみ処理（大文字小文字を無視）
        if affected.get("package", {}).get("name", "").lower() != package_name.lower():
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    fixed.append(event["fixed"])
    return fixed


def _query_osv(
    package_name: str, version: str | None, ecosystem: str
) -> list[VulnerabilityFinding]:
    """OSV API にパッケージの脆弱性情報を問い合わせる。
    バージョン指定がある場合はそのバージョンに影響する CVE に絞り込む。
    """
    payload: dict = {
        "package": {"name": package_name, "ecosystem": ecosystem}
    }
    if version:
        payload["version"] = version

    try:
        with httpx.Client(timeout=OSV_TIMEOUT) as client:
            resp = client.post(OSV_API_URL, json=payload)
            resp.raise_for_status()
            vulns = resp.json().get("vulns", [])
    except httpx.HTTPError as exc:
        # OSV API エラーはスキャン全体を止めず警告ログのみ
        logger.warning("OSV API error for %s: %s", package_name, exc)
        return []

    findings: list[VulnerabilityFinding] = []
    for v in vulns:
        aliases = v.get("aliases", [])
        # CVE ID を優先して使用し、なければ OSV 固有 ID を使用
        vuln_id = next((a for a in aliases if a.startswith("CVE-")), v.get("id", ""))
        fixed_versions = _extract_fixed_versions(v, package_name)
        refs = [r["url"] for r in v.get("references", []) if "url" in r]

        findings.append(VulnerabilityFinding(
            package_name=package_name,
            package_version=version,
            source="OSV",
            vuln_id=vuln_id,
            severity=_extract_severity(v),
            summary=v.get("summary", ""),
            details=v.get("details"),
            fixed_versions=fixed_versions,
            references=refs[:5],
        ))

    logger.debug("OSV: %s@%s → %d findings", package_name, version, len(findings))
    return findings


def _query_kev(db: Session, package_name: str) -> list[VulnerabilityFinding]:
    """CISA KEV DB からパッケージ名に関連する脆弱性を検索する。
    vendor_project と product を部分一致で検索する。
    """
    keyword = f"%{package_name}%"
    items = (
        db.query(Vulnerability)
        .filter(
            or_(
                Vulnerability.vendor_project.ilike(keyword),
                Vulnerability.product.ilike(keyword),
            )
        )
        .order_by(Vulnerability.date_added.desc())
        .limit(10)
        .all()
    )

    findings: list[VulnerabilityFinding] = []
    for item in items:
        findings.append(VulnerabilityFinding(
            package_name=package_name,
            package_version=None,
            source="CISA_KEV",
            vuln_id=item.cve_id,
            severity=None,  # KEV は深刻度を保持しない（実際に悪用済みが前提）
            summary=item.vulnerability_name,
            details=item.description,
            fixed_versions=[],
            references=[],
        ))

    logger.debug("CISA_KEV: %s → %d findings", package_name, len(findings))
    return findings


def _deduplicate(findings: list[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
    """同一パッケージ × 同一 CVE ID の重複を除去する。OSV の情報を優先する。"""
    seen: dict[str, VulnerabilityFinding] = {}
    for f in findings:
        key = f"{f.package_name.lower()}:{f.vuln_id}"
        # OSV の情報の方が詳細なため、既存エントリが CISA_KEV なら OSV で上書き
        if key not in seen or f.source == "OSV":
            seen[key] = f
    return list(seen.values())


def _parse_requirements(text: str) -> list[PackageInput]:
    """requirements.txt 形式のテキストをパースして PackageInput リストを返す。
    コメント行・空行・オプション行（-r, --index-url 等）はスキップする。
    """
    packages: list[PackageInput] = []
    for line in text.splitlines():
        line = line.strip()
        # コメント・空行・pip オプション行をスキップ
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # セミコロン以降の環境マーカーを除去（例: fastapi; python_version>="3.8"）
        line = line.split(";")[0].strip()
        # パッケージ名を分離（==, >=, <=, ~=, != のバージョン指定に対応）
        name_match = re.split(r"[><=!~@\s\[]+", line, maxsplit=1)
        name = name_match[0].strip()
        # == で固定されているバージョンを抽出（範囲指定は除く）
        version: str | None = None
        if "==" in line:
            version = line.split("==")[1].split(",")[0].strip()
        if name:
            packages.append(PackageInput(name=name, version=version, ecosystem="PyPI"))
    return packages


def _parse_package_json(text: str) -> list[PackageInput]:
    """package.json の内容をパースして PackageInput リストを返す。
    dependencies と devDependencies の両方を対象にする。
    バージョンのプレフィックス（^, ~, >=）は除去して渡す。
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"package.json のパースに失敗しました: {exc}",
        ) from exc

    packages: list[PackageInput] = []
    for section in ("dependencies", "devDependencies"):
        for name, ver_str in data.get(section, {}).items():
            # バージョン範囲記号を除去して数値バージョンを抽出
            clean_ver = re.sub(r"^[^0-9]*", "", str(ver_str)).split(" ")[0] or None
            packages.append(PackageInput(name=name, version=clean_ver, ecosystem="npm"))
    return packages


def _get_previous_vuln_ids(db: Session, scan_type: str) -> set[str]:
    """同一 scan_type の直前スキャン結果から脆弱性 ID の集合を取得する。
    前回スキャンが存在しない場合は空集合を返す。
    """
    prev = (
        db.query(ScanResult)
        .filter(ScanResult.scan_type == scan_type)
        .order_by(ScanResult.scanned_at.desc())
        .first()
    )
    if prev is None:
        return set()
    return {f.get("vuln_id", "") for f in (prev.findings or []) if f.get("vuln_id")}


def _run_scan(db: Session, packages: list[PackageInput], scan_type: str) -> ScanResponse:
    """パッケージリストをスキャンして ScanResponse を返し、結果を DB に保存する。
    前回スキャンとの差分（新規脆弱性）を検出して Slack 通知を送る。
    """
    all_findings: list[VulnerabilityFinding] = []

    # 前回スキャンの脆弱性 ID を先に取得（今回の保存前に行う）
    prev_vuln_ids = _get_previous_vuln_ids(db, scan_type)

    for pkg in packages:
        # OSV API で検索（バージョン指定があればそのバージョンに限定）
        all_findings.extend(_query_osv(pkg.name, pkg.version, pkg.ecosystem))
        # CISA KEV DB で製品名検索
        all_findings.extend(_query_kev(db, pkg.name))

    deduped = _deduplicate(all_findings)

    # スキャン結果を DB に永続化
    record = ScanResult(
        scan_type=scan_type,
        scanned_packages=len(packages),
        total_findings=len(deduped),
        findings=[f.model_dump() for f in deduped],
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    logger.info(
        "scan completed: type=%s, packages=%d, findings=%d, id=%d",
        scan_type, len(packages), len(deduped), record.id,
    )

    # 前回スキャンと比較して新規発見の脆弱性を Slack 通知
    current_vuln_ids = {f.vuln_id for f in deduped if f.vuln_id}
    new_vuln_ids = sorted(current_vuln_ids - prev_vuln_ids)
    notify_scan_diff(new_vuln_ids, scan_type)

    return ScanResponse(
        scanned_packages=len(packages),
        total_findings=len(deduped),
        findings=deduped,
    )


def _to_scan_result_out(record: ScanResult) -> ScanResultOut:
    """ScanResult ORM モデルを ScanResultOut スキーマに変換する。"""
    findings = [VulnerabilityFinding(**f) for f in (record.findings or [])]
    return ScanResultOut(
        id=record.id,
        scan_type=record.scan_type,
        scanned_packages=record.scanned_packages,
        total_findings=record.total_findings,
        findings=findings,
        scanned_at=record.scanned_at.isoformat(),
    )


# ── エンドポイント ────────────────────────────────────────────────


@router.post(
    "",
    response_model=ScanResponse,
    summary="パッケージ脆弱性スキャン",
    description=(
        "指定したパッケージを **OSV**（Open Source Vulnerabilities）と "
        "**CISA KEV** の両方から横断検索し、既知の脆弱性一覧を返す。"
        "スキャン結果は履歴として保存される。"
    ),
)
def scan_packages(
    db: Annotated[Session, Depends(get_db)],
    request: ScanRequest,
) -> ScanResponse:
    """パッケージリストの脆弱性をスキャンする。

    - OSV: バージョン指定があればそのバージョンに影響する CVE のみを返す
    - CISA KEV: パッケージ名をベンダー名・製品名で部分一致検索
    - 同一 CVE の重複は自動除去（OSV の詳細情報を優先）
    """
    return _run_scan(db, request.packages, scan_type="packages")


@router.post(
    "/requirements",
    response_model=ScanResponse,
    summary="requirements.txt スキャン",
    description=(
        "`requirements.txt` の内容をそのまま貼り付けてスキャンする。"
        "各パッケージを OSV と CISA KEV で検索し、脆弱性一覧を返す。"
        "スキャン結果は履歴として保存される。"
    ),
)
def scan_requirements(
    db: Annotated[Session, Depends(get_db)],
    body: Annotated[str, Body(media_type="text/plain")],
) -> ScanResponse:
    """requirements.txt 形式のテキストをパースしてスキャンする。

    Content-Type: text/plain でリクエストボディに requirements.txt の内容を送る。
    """
    packages = _parse_requirements(body)
    if not packages:
        raise HTTPException(
            status_code=422,
            detail="パッケージが見つかりませんでした。requirements.txt 形式で入力してください。",
        )
    return _run_scan(db, packages, scan_type="requirements")


@router.post(
    "/package-json",
    response_model=ScanResponse,
    summary="package.json スキャン（npm）",
    description=(
        "`package.json` の内容をそのまま貼り付けてスキャンする。"
        "`dependencies` と `devDependencies` の両方を OSV（npm エコシステム）と "
        "CISA KEV で検索する。スキャン結果は履歴として保存される。"
    ),
)
def scan_package_json(
    db: Annotated[Session, Depends(get_db)],
    body: Annotated[str, Body(media_type="text/plain")],
) -> ScanResponse:
    """package.json の内容をパースして npm パッケージをスキャンする。

    Content-Type: text/plain でリクエストボディに package.json の内容を送る。
    """
    packages = _parse_package_json(body)
    if not packages:
        raise HTTPException(
            status_code=422,
            detail=(
                "パッケージが見つかりませんでした。"
                "dependencies または devDependencies が存在する package.json を入力してください。"
            ),
        )
    return _run_scan(db, packages, scan_type="package-json")


@router.get(
    "/history",
    response_model=list[ScanResultOut],
    summary="スキャン履歴一覧",
    description="過去のスキャン結果を新しい順に返す（最大 50 件）。",
)
def list_scan_history(
    db: Annotated[Session, Depends(get_db)],
    limit: int = Query(20, ge=1, le=50, description="取得件数（最大 50）"),
) -> list[ScanResultOut]:
    """スキャン実行履歴を一覧で返す。"""
    records = (
        db.query(ScanResult)
        .order_by(ScanResult.scanned_at.desc())
        .limit(limit)
        .all()
    )
    return [_to_scan_result_out(r) for r in records]


@router.get(
    "/history/{scan_id}",
    response_model=ScanResultOut,
    summary="スキャン結果詳細",
    description="指定した ID のスキャン結果を返す。",
)
def get_scan_result(
    scan_id: int,
    db: Annotated[Session, Depends(get_db)],
) -> ScanResultOut:
    """指定した ID のスキャン結果を返す。存在しない場合は 404。"""
    record = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=f"スキャン結果 ID={scan_id} は見つかりませんでした。",
        )
    return _to_scan_result_out(record)
