"""OSVレコードのSTIX 2.1 Vulnerability SDOへの変換（Issue #134のOSV拡張）。

KEV向けに実装したSTIX 2.1変換（app.kev.stix）をOSVへ拡張する。共通処理
（タイムスタンプ変換・IDネームスペース）は app.core.stix を利用する。

OSVは `(osv_id, ecosystem, package_name)` の複合キーが自然キーのため
（1つのOSV IDが複数パッケージに影響する場合、行ごとに異なるSTIXオブジェクトに
なる）、KEVのCVE単位とは異なりこの3値からオブジェクトIDを生成する。
"""
import uuid
from typing import Any

from app.core.stix import STIX_ID_NAMESPACE, stix_timestamp
from app.osv.models import OsvVulnerability


def stix_vulnerability_id(osv_id: str, ecosystem: str, package_name: str) -> str:
    """(osv_id, ecosystem, package_name) からSTIX Vulnerability SDOの決定論的なIDを組み立てる。

    TAXIIコレクションの/objects/{object-id}/エンドポイントで単体取得する際にも
    同じ関数を使い、常に同じIDで参照できるようにする。
    """
    return (
        "vulnerability--"
        f"{uuid.uuid5(STIX_ID_NAMESPACE, f'osv:{osv_id}:{ecosystem}:{package_name}')}"
    )


def build_stix_vulnerability(vuln: OsvVulnerability) -> dict[str, Any]:
    """OSVレコード1件をSTIX 2.1のVulnerability SDOに変換する。"""
    description = vuln.summary
    if vuln.details:
        description += f"\n\n{vuln.details}"

    external_references: list[dict[str, str]] = [
        {
            "source_name": "osv",
            "external_id": vuln.osv_id,
            "url": f"https://osv.dev/vulnerability/{vuln.osv_id}",
        },
    ]
    # aliasesのうちCVE IDのみ外部参照として追加する（CVE以外のエイリアス
    # 〈GHSA等の他DB ID〉は対応するsource_nameの定義が無いため対象外）
    for alias in vuln.aliases:
        if alias.startswith("CVE-"):
            external_references.append({"source_name": "cve", "external_id": alias})

    stix_obj: dict[str, Any] = {
        "type": "vulnerability",
        "spec_version": "2.1",
        "id": stix_vulnerability_id(vuln.osv_id, vuln.ecosystem, vuln.package_name),
        "created": stix_timestamp(vuln.published),
        "modified": stix_timestamp(vuln.modified),
        "name": vuln.osv_id,
        "description": description,
        "external_references": external_references,
        # STIXコア仕様に無い概念のため、x_接頭辞のカスタムプロパティとして付与する
        # （STIX 2.1が許容する拡張方法。KEVのEPSS付与と同じ方針）
        "x_ecosystem": vuln.ecosystem,
        "x_package_name": vuln.package_name,
    }
    if vuln.cvss_score is not None:
        stix_obj["x_cvss_score"] = vuln.cvss_score
    return stix_obj


def build_stix_bundle(vulns: list[OsvVulnerability]) -> dict[str, Any]:
    """複数のOSVレコードをSTIX 2.1のBundleにまとめる（TAXII配信・複数行返却用）。"""
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [build_stix_vulnerability(v) for v in vulns],
    }
