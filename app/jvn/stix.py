"""JVNレコードのSTIX 2.1 Vulnerability SDOへの変換（Issue #134のJVN拡張）。

KEV向けに実装したSTIX 2.1変換（app.kev.stix）をJVNへ拡張する。共通処理
（タイムスタンプ変換・IDネームスペース）は app.core.stix を利用する。

JVNDB IDは一意キーのため、KEVのCVE単位と同様に単一の識別子からオブジェクトIDを
生成する。
"""
import uuid
from typing import Any

from app.core.stix import STIX_ID_NAMESPACE, stix_timestamp
from app.jvn.models import JvnVulnerability


def stix_vulnerability_id(jvndb_id: str) -> str:
    """JVNDB IDからSTIX Vulnerability SDOの決定論的なIDを組み立てる。

    TAXIIコレクションの/objects/{object-id}/エンドポイントで単体取得する際にも
    同じ関数を使い、常に同じIDで参照できるようにする。
    """
    return f"vulnerability--{uuid.uuid5(STIX_ID_NAMESPACE, f'jvn:{jvndb_id}')}"


def build_stix_vulnerability(vuln: JvnVulnerability) -> dict[str, Any]:
    """JVNレコード1件をSTIX 2.1のVulnerability SDOに変換する。"""
    description = f"{vuln.title}\n\n{vuln.overview}"

    external_references: list[dict[str, str]] = [
        {"source_name": "jvndb", "external_id": vuln.jvndb_id, "url": vuln.jvn_url},
    ]
    for cve_id in vuln.cve_ids:
        external_references.append({"source_name": "cve", "external_id": cve_id})

    stix_obj: dict[str, Any] = {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": stix_vulnerability_id(vuln.jvndb_id),
        "created": stix_timestamp(vuln.date_published),
        "modified": stix_timestamp(vuln.date_last_modified),
        "name": vuln.jvndb_id,
        "description": description,
        "external_references": external_references,
    }
    # STIXコア仕様に無い概念のため、x_接頭辞のカスタムプロパティとして付与する
    # （STIX 2.1が許容する拡張方法。KEVのEPSS付与と同じ方針）
    if vuln.cvss_score is not None:
        stix_obj["x_cvss_score"] = vuln.cvss_score
    if vuln.cvss_vector is not None:
        stix_obj["x_cvss_vector"] = vuln.cvss_vector
    return stix_obj


def build_stix_bundle(vulns: list[JvnVulnerability]) -> dict[str, Any]:
    """複数のJVNレコードをSTIX 2.1のBundleにまとめる（TAXII配信用）。"""
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [build_stix_vulnerability(v) for v in vulns],
    }
