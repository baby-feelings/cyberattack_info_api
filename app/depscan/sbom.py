"""DEPSCAN検知結果のSBOM（Software Bill of Materials）エクスポート（Issue #133）。

CycloneDX 1.5・SPDX 2.3 形式でのエクスポートに対応する。パッケージ識別には
purl（Package URL、https://github.com/package-url/purl-spec）を使用し、他の
SBOM/SCAツールとの相互運用性を高める。

対応範囲: エクスポート（読み取り専用）のみ。外部SBOMの入力受け付け・VEX状態
拡張はIssue #133本文の別提案として、必要になったタイミングで別途対応する
（スコープ外）。
"""
import urllib.parse
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.depscan.models import DependencyFinding

# エコシステム名 → purl type のマッピング（package-url/purl-spec の既知タイプに準拠）
_ECOSYSTEM_TO_PURL_TYPE = {
    "PyPI": "pypi",
    "npm": "npm",
    "Go": "golang",
    "Maven": "maven",
    "RubyGems": "gem",
    "NuGet": "nuget",
    "crates.io": "cargo",
    "Packagist": "composer",
    "Hex": "hex",
    "Pub": "pub",
}


def build_purl(ecosystem: str, package_name: str, version: str) -> str:
    """パッケージ情報からpurl文字列を組み立てる（best-effort）。

    namespace/name分割が必要なエコシステム（Maven: groupId:artifactId、
    Packagist: vendor/name、npm: @scope/name）はここで分解する。それ以外
    （Go等）は完全な識別子をそのままnameとして扱う（購入者側ツールの多くも
    同様の単純化を行っており、実務上十分な精度）。
    """
    purl_type = _ECOSYSTEM_TO_PURL_TYPE.get(ecosystem, ecosystem.lower())
    namespace: str | None = None
    name = package_name

    if ecosystem == "Maven" and ":" in package_name:
        namespace, name = package_name.split(":", 1)
    elif ecosystem == "Packagist" and "/" in package_name:
        namespace, name = package_name.split("/", 1)
    elif ecosystem == "npm" and package_name.startswith("@") and "/" in package_name:
        namespace, name = package_name[1:].split("/", 1)
    elif ecosystem == "PyPI":
        # PyPI正規化ルール（PEP 503）: 大文字小文字・区切り文字（_ . -）の違いを無視する
        name = package_name.lower().replace("_", "-").replace(".", "-")

    encoded_name = urllib.parse.quote(name, safe="")
    version_part = f"@{urllib.parse.quote(version, safe='')}" if version else ""
    if namespace:
        encoded_namespace = urllib.parse.quote(namespace, safe="")
        return f"pkg:{purl_type}/{encoded_namespace}/{encoded_name}{version_part}"
    return f"pkg:{purl_type}/{encoded_name}{version_part}"


def build_cyclonedx_sbom(
    repo_full_name: str, findings: list[DependencyFinding],
) -> dict[str, Any]:
    """CycloneDX 1.5 JSON形式のSBOMを構築する。

    パッケージ（components）は(ecosystem, package_name, installed_version)単位で
    重複排除し、脆弱性（vulnerabilities）は元のfindingごとに1件、affectsで
    該当componentのbom-refを参照する（1パッケージに複数CVEが紐づく場合、
    componentは1つにまとまりvulnerabilitiesだけが複数件になる）。
    """
    components: dict[tuple[str, str, str], dict[str, Any]] = {}
    vulnerabilities: list[dict[str, Any]] = []

    for finding in findings:
        key = (finding.ecosystem, finding.package_name, finding.installed_version)
        if key not in components:
            purl = build_purl(finding.ecosystem, finding.package_name, finding.installed_version)
            components[key] = {
                "type": "library",
                "bom-ref": purl,
                "name": finding.package_name,
                "version": finding.installed_version,
                "purl": purl,
            }
        bom_ref = components[key]["bom-ref"]

        vuln: dict[str, Any] = {
            "id": finding.osv_id,
            "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{finding.osv_id}"},
            "description": finding.summary,
            "affects": [{"ref": bom_ref}],
        }
        if finding.cve_ids:
            vuln["references"] = [
                {"id": cve_id, "source": {"name": "NVD"}} for cve_id in finding.cve_ids
            ]
        if finding.severity or finding.cvss_score is not None:
            rating: dict[str, Any] = {}
            if finding.severity:
                rating["severity"] = finding.severity.lower()
            if finding.cvss_score is not None:
                rating["score"] = finding.cvss_score
                rating["method"] = "CVSSv3"
            vuln["ratings"] = [rating]
        if finding.fixed_versions:
            vuln["recommendation"] = f"Upgrade to {', '.join(finding.fixed_versions)}"
        vulnerabilities.append(vuln)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {"type": "application", "name": repo_full_name},
        },
        "components": list(components.values()),
        "vulnerabilities": vulnerabilities,
    }


def build_spdx_sbom(
    repo_full_name: str, findings: list[DependencyFinding],
) -> dict[str, Any]:
    """SPDX 2.3 JSON形式のSBOM（パッケージ一覧）を構築する。

    SPDX 2.3のコア仕様には脆弱性を表現する概念が無い（SPDX 3.0のSecurity
    プロファイルや別建てのVEX文書で扱うのが標準的で、Issue #133でスコープ外と
    したVEX拡張の実装が前提になる）。そのためpackagesのみを出力する
    （脆弱性検知結果自体はCycloneDX形式かGET /api/depscanで確認する）。
    """
    seen: set[tuple[str, str, str]] = set()
    packages: list[dict[str, Any]] = []

    for finding in findings:
        key = (finding.ecosystem, finding.package_name, finding.installed_version)
        if key in seen:
            continue
        seen.add(key)
        purl = build_purl(finding.ecosystem, finding.package_name, finding.installed_version)
        packages.append({
            "SPDXID": f"SPDXRef-Package-{len(packages)}",
            "name": finding.package_name,
            "versionInfo": finding.installed_version,
            "downloadLocation": "NOASSERTION",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }],
        })

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": repo_full_name,
        "documentNamespace": (
            f"https://cyberattack-info-api.internal/spdx/"
            f"{urllib.parse.quote(repo_full_name, safe='')}/{uuid4()}"
        ),
        "creationInfo": {
            "created": now,
            "creators": ["Tool: cyberattack-info-api-DEPSCAN"],
        },
        "packages": packages,
    }
