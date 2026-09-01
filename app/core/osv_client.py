"""OSV (Open Source Vulnerabilities) REST API の汎用クライアント。

OSV エコシステム固有のビジネスロジック（DB Upsert 等）は持たず、OSV API
(https://api.osv.dev/v1/) への問い合わせと結果の整形のみを担う。
`app.osv.crawler`（OSV 自体のクロール）と `app.depscan.crawler`
（依存ライブラリ脆弱性スキャンでのリアルタイム照合）の両方から利用される。
"""
from typing import Any

import httpx

# OSV REST API ベース URL
OSV_API_BASE = "https://api.osv.dev/v1"

# 1回の /v1/querybatch で送れる最大クエリ数
BATCH_SIZE = 1000


def parse_severity(vuln: dict[str, Any]) -> tuple[str | None, float | None]:
    """OSV エントリから重要度ラベルと CVSS スコアを抽出する。

    優先順位:
    1. database_specific.severity（GitHub Advisory Database が付与する文字列）
    2. database_specific.cvss.score（数値スコア）
    3. severity[].score が数値の場合

    Returns:
        (severity_label, cvss_score) のタプル
    """
    db_specific = vuln.get("database_specific", {}) or {}

    # 1. database_specific.severity（CRITICAL/HIGH/MEDIUM/LOW 文字列）
    sev_str = (db_specific.get("severity") or "").upper()
    if sev_str in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
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


def extract_fixed_versions(affected: dict[str, Any]) -> list[str]:
    """affected エントリの ranges から修正済みバージョン（fixed イベント）を抽出する。"""
    fixed: list[str] = []
    for rng in affected.get("ranges", []):
        for event in rng.get("events", []):
            if "fixed" in event:
                fixed.append(event["fixed"])
    return fixed


def query_packages_batch(
    packages: list[tuple[str, str]],  # [(package_name, ecosystem), ...]
) -> list[dict[str, Any]]:
    """/v1/querybatch で複数パッケージを一括クエリして {id, modified} リストを返す。

    querybatch は id と modified のみ返すため、詳細は別途 fetch_vuln_by_id で取得する。

    Args:
        packages: (パッケージ名, エコシステム) のタプルリスト（最大 BATCH_SIZE 件）

    Returns:
        {"id": ..., "modified": ...} 辞書のリスト（重複 ID は除去済み）
    """
    if not packages:
        return []

    queries = [
        {"package": {"name": pkg, "ecosystem": eco}}
        for pkg, eco in packages
    ]

    with httpx.Client(timeout=60.0) as client:
        resp = client.post(
            f"{OSV_API_BASE}/querybatch",
            json={"queries": queries},
        )
        resp.raise_for_status()

    data = resp.json()
    # 脆弱性を ID でユニーク化（複数パッケージが同じ CVE に影響する場合の重複除去）
    seen: set[str] = set()
    refs: list[dict[str, Any]] = []
    for result in data.get("results", []):
        for v in result.get("vulns", []):
            vid = v.get("id", "")
            if vid and vid not in seen:
                seen.add(vid)
                refs.append({"id": vid, "modified": v.get("modified", "")})

    return refs


def query_versions_batch(
    items: list[tuple[str, str, str]],  # [(ecosystem, package_name, version), ...]
) -> dict[tuple[str, str, str], list[str]]:
    """/v1/querybatch にバージョン指定でバッチクエリし、各パッケージ×バージョンに
    ヒットした脆弱性 ID を返す（DEPSCAN 機能から使用）。

    querybatch はクエリと結果を同じ順序の配列で返す仕様のため、位置合わせで
    (ecosystem, package_name, version) と結果を対応付ける。

    Args:
        items: (エコシステム, パッケージ名, バージョン) のタプルリスト

    Returns:
        {(ecosystem, package_name, version): [osv_id, ...]} の辞書
        （ヒットなしのキーは含まない）
    """
    if not items:
        return {}

    result_map: dict[tuple[str, str, str], list[str]] = {}

    with httpx.Client(timeout=60.0) as client:
        for i in range(0, len(items), BATCH_SIZE):
            chunk = items[i: i + BATCH_SIZE]
            queries = [
                {"version": version, "package": {"name": name, "ecosystem": eco}}
                for eco, name, version in chunk
            ]
            resp = client.post(
                f"{OSV_API_BASE}/querybatch",
                json={"queries": queries},
            )
            resp.raise_for_status()
            results = resp.json().get("results", [])

            for item, result in zip(chunk, results, strict=False):
                vuln_ids = [v["id"] for v in result.get("vulns", []) if v.get("id")]
                if vuln_ids:
                    result_map[item] = vuln_ids

    return result_map


def fetch_vuln_by_id(osv_id: str) -> dict[str, Any]:
    """GET /v1/vulns/{id} で脆弱性の完全な情報（affected・severity 等）を取得する。"""
    with httpx.Client(timeout=30.0) as client:
        resp = client.get(f"{OSV_API_BASE}/vulns/{osv_id}")
        resp.raise_for_status()
    return resp.json()
