"""CISA KEVレコードのSTIX 2.1 Vulnerability SDOへの変換（Issue #134）。

複数の脆弱性DB・APIを跨いで情報を収集する際、標準フォーマットの欠如が
相互運用の障害となっている問題に対応する。MISP等の既存CTI共有基盤や
SIEM/TIPとの連携を想定し、KEVレコードをSTIX 2.1のVulnerability SDO
形式に変換する。

対応範囲: KEVのみ（Issue #134本文の具体例
`GET /api/vulnerabilities/{cve_id}?format=stix` に準拠）。OSV/JVNへの
拡張は必要になったタイミングで別途対応する。
"""
import uuid
from datetime import date, datetime, time, timezone
from typing import Any

from app.kev.models import Vulnerability

# STIXオブジェクトIDを安定させるための名前空間UUID（uuid5用、DNS名前空間の
# 標準UUID）。同じCVEに対して常に同じIDを生成することで、TAXIIクライアント側の
# 差分取得（added_after等）や重複排除が正しく機能する
_STIX_ID_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")

_CISA_KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def stix_vulnerability_id(cve_id: str) -> str:
    """CVE IDからSTIX Vulnerability SDOの決定論的なIDを組み立てる。

    TAXIIコレクションの/objects/{object-id}/エンドポイントで単体取得する際にも
    同じ関数を使い、常に同じIDで参照できるようにする。
    """
    return f"vulnerability--{uuid.uuid5(_STIX_ID_NAMESPACE, f'cisa-kev:{cve_id}')}"


def _stix_timestamp(dt: datetime) -> str:
    """STIXタイムスタンプ形式（RFC3339、ミリ秒・Z終端）に変換する。"""
    dt_utc = dt.astimezone(timezone.utc)
    return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt_utc.microsecond // 1000:03d}Z"


def _to_datetime(d: date) -> datetime:
    return datetime.combine(d, time.min, tzinfo=timezone.utc)


def build_stix_vulnerability(vuln: Vulnerability) -> dict[str, Any]:
    """CISA KEVレコード1件をSTIX 2.1のVulnerability SDOに変換する。"""
    created_at = _to_datetime(vuln.date_added)
    modified_at = vuln.updated_at if vuln.updated_at is not None else created_at

    description = f"{vuln.vulnerability_name}\n\n{vuln.description}"
    if vuln.required_action:
        description += f"\n\nRequired Action: {vuln.required_action}"

    stix_obj: dict[str, Any] = {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": stix_vulnerability_id(vuln.cve_id),
        "created": _stix_timestamp(created_at),
        "modified": _stix_timestamp(modified_at),
        "name": vuln.cve_id,
        "description": description,
        "external_references": [
            {"source_name": "cve", "external_id": vuln.cve_id},
            {
                "source_name": "cisa-kev",
                "description": "CISA Known Exploited Vulnerabilities Catalog",
                "url": _CISA_KEV_URL,
            },
        ],
    }
    # STIXコア仕様にEPSSの概念は無いため、x_接頭辞のカスタムプロパティとして
    # 付与する（STIX 2.1が許容する拡張方法。custom propertyはx_で始める規約）
    if vuln.epss_score is not None:
        stix_obj["x_epss_score"] = vuln.epss_score
        stix_obj["x_epss_percentile"] = vuln.epss_percentile
    return stix_obj


def build_stix_bundle(vulns: list[Vulnerability]) -> dict[str, Any]:
    """複数のKEVレコードをSTIX 2.1のBundleにまとめる（TAXII配信用）。"""
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [build_stix_vulnerability(v) for v in vulns],
    }
