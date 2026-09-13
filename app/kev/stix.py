"""CISA KEVレコードのSTIX 2.1 Vulnerability SDOへの変換（Issue #134）。

複数の脆弱性DB・APIを跨いで情報を収集する際、標準フォーマットの欠如が
相互運用の障害となっている問題に対応する。MISP等の既存CTI共有基盤や
SIEM/TIPとの連携を想定し、KEVレコードをSTIX 2.1のVulnerability SDO
形式に変換する。

対応範囲: KEV/OSV/JVNの3ドメイン（Issue #134本文の具体例
`GET /api/vulnerabilities/{cve_id}?format=stix` に準拠したKEV対応がベース。
OSV/JVNへの拡張はIssue #134の後続対応として実装済み。OSV/JVN向けの変換は
それぞれ app.osv.stix / app.jvn.stix を参照）。

タイムスタンプ変換・IDネームスペースといった共通処理は app.core.stix に
切り出してあり、本モジュールはそれをimportして使う（DRY。既存のオブジェクトID
生成結果は変更していない）。
"""
import uuid
from datetime import date, datetime, time, timezone
from typing import Any

from app.core.stix import STIX_ID_NAMESPACE, stix_timestamp
from app.kev.models import Vulnerability

_CISA_KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def stix_vulnerability_id(cve_id: str) -> str:
    """CVE IDからSTIX Vulnerability SDOの決定論的なIDを組み立てる。

    TAXIIコレクションの/objects/{object-id}/エンドポイントで単体取得する際にも
    同じ関数を使い、常に同じIDで参照できるようにする。
    """
    return f"vulnerability--{uuid.uuid5(STIX_ID_NAMESPACE, f'cisa-kev:{cve_id}')}"


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
        "created": stix_timestamp(created_at),
        "modified": stix_timestamp(modified_at),
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
