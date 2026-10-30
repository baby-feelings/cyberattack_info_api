"""検知の例外を VEX（Vulnerability Exploitability eXchange）として出力する（OpenVEX・CycloneDX）。

VEX は「その脆弱性が、この製品で悪用できるか」を伝える文書。誤検知・影響なしは `not_affected`、
受容（修正せずに残す）は `affected` で、対応（期限つきの受容）を `action_statement` に書く。
対象は依存ライブラリ（DEPSCAN）の例外のみ（コードの診断結果は、脆弱性の識別子を持たないため）。
"""
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.core.osv_client import osv_vulnerability_url
from app.depscan.models import DependencyFinding
from app.depscan.sbom import build_purl
from app.finding_exceptions.matching import KEY_SEPARATOR
from app.finding_exceptions.models import (
    STATUS_ACCEPTED,
    STATUS_FALSE_POSITIVE,
    STATUS_NOT_AFFECTED,
    FindingException,
)

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
_AUTHOR = "cyberattack_info_api"

# CycloneDX の analysis.state。受容は「悪用できる状態のまま（修正しない）」を表す
_CYCLONEDX_STATE = {
    STATUS_ACCEPTED: "exploitable",
    STATUS_FALSE_POSITIVE: "false_positive",
    STATUS_NOT_AFFECTED: "not_affected",
}


def _expiry_text(exc: FindingException) -> str:
    return f"（期限 {exc.expires_at.date().isoformat()}）" if exc.expires_at else ""


def cyclonedx_analysis(exc: FindingException) -> dict[str, Any]:
    """CycloneDX の脆弱性の `analysis`（SBOM・VEX の両方で使う）。"""
    analysis: dict[str, Any] = {
        "state": _CYCLONEDX_STATE[exc.status],
        "detail": f"{exc.reason}{_expiry_text(exc)}",
    }
    if exc.status == STATUS_ACCEPTED:
        analysis["response"] = ["will_not_fix"]
    return analysis


def analysis_by_finding(
    exceptions: Iterable[FindingException],
) -> dict[tuple[str, str, str], dict[str, Any]]:
    """依存ライブラリの例外を、(ecosystem, package, osv_id) で引ける辞書にする（SBOM 用）。"""
    result: dict[tuple[str, str, str], dict[str, Any]] = {}
    for exc in exceptions:
        parts = exc.finding_key.split(KEY_SEPARATOR)
        if len(parts) == 3:
            result[(parts[0], parts[1], parts[2])] = cyclonedx_analysis(exc)
    return result


def _statement(exc: FindingException, finding: DependencyFinding) -> dict[str, Any]:
    """OpenVEX の statement 1件。"""
    statement: dict[str, Any] = {
        "vulnerability": {
            "name": finding.osv_id,
            "@id": osv_vulnerability_url(finding.osv_id),
            **({"aliases": list(finding.cve_ids)} if finding.cve_ids else {}),
        },
        "products": [{
            "@id": build_purl(
                finding.ecosystem, finding.package_name, finding.installed_version,
            ),
        }],
    }
    if exc.status == STATUS_ACCEPTED:
        # affected には、対応（action_statement）が必須
        statement["status"] = "affected"
        statement["action_statement"] = f"受容: {exc.reason}{_expiry_text(exc)}"
    else:
        # not_affected には、justification か impact_statement が必須
        statement["status"] = "not_affected"
        statement["impact_statement"] = exc.reason
    return statement


def build_openvex(
    repo_full_name: str, rows: list[tuple[FindingException, DependencyFinding]],
) -> dict[str, Any]:
    """OpenVEX 0.2.0 の文書を作る。"""
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": f"urn:uuid:{uuid4()}",
        "author": _AUTHOR,
        "role": f"owner of {repo_full_name}",
        "timestamp": datetime.now(UTC).isoformat(),
        "version": 1,
        "statements": [_statement(exc, finding) for exc, finding in rows],
    }


def build_cyclonedx_vex(
    repo_full_name: str, rows: list[tuple[FindingException, DependencyFinding]],
) -> dict[str, Any]:
    """CycloneDX 1.5 の VEX 文書を作る（脆弱性と analysis のみ。components は持たない）。"""
    vulnerabilities = []
    for exc, finding in rows:
        vulnerabilities.append({
            "id": finding.osv_id,
            "source": {"name": "OSV", "url": osv_vulnerability_url(finding.osv_id)},
            "analysis": cyclonedx_analysis(exc),
            "affects": [{
                "ref": build_purl(
                    finding.ecosystem, finding.package_name, finding.installed_version,
                ),
            }],
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "component": {"type": "application", "name": repo_full_name},
        },
        "vulnerabilities": vulnerabilities,
    }
