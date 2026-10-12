"""パッケージ×バージョンを OSV に照合し、検知レコード（DependencyFinding 相当）を構築する。"""
import logging
import re
from typing import Any

import httpx

from app.core.osv_client import fetch_vuln_by_id, parse_severity, query_versions_batch
from app.crawler_logs.writer import now_utc
from app.depscan.manifests import DepKey
from app.depscan.registry_client import fetch_latest_version, is_newer_version

logger = logging.getLogger(__name__)


def _normalize_package_name(name: str) -> str:
    """OSV の package.name とロックファイル上の名前を突き合わせるための正規化。"""
    return re.sub(r"[-_.]+", "-", name).lower()


def _last_affected_versions(
    vuln: dict[str, Any], ecosystem: str, package_name: str,
) -> list[str]:
    """OSV エントリのうち、対象パッケージの affected から last_affected を集める。"""
    target = _normalize_package_name(package_name)
    return [
        event["last_affected"]
        for affected in vuln.get("affected", [])
        if (affected.get("package") or {}).get("ecosystem") == ecosystem
        and _normalize_package_name((affected.get("package") or {}).get("name", "")) == target
        for rng in affected.get("ranges", [])
        for event in rng.get("events", [])
        if "last_affected" in event
    ]


def _infer_fixed_versions(
    vuln: dict[str, Any], ecosystem: str, package_name: str,
    latest_cache: dict[tuple[str, str], str | None],
) -> list[str]:
    """OSV に `fixed` が無く `last_affected` だけある脆弱性の修正版をレジストリから補う。

    OSV が影響範囲の上限しか載せていない場合（例: accelerate、影響は 1.14.0 まで）、
    修正版が空のため「修正版なし」と誤表示されていた。レジストリの最新版が
    last_affected より新しければ、それは影響を受けないため修正版の目安として返す。
    判定できない場合（last_affected なし・最新版を取得できない・版の比較に確信が持てない）
    は空リストを返し、従来どおり修正版なしとして扱う。
    """
    last_versions = _last_affected_versions(vuln, ecosystem, package_name)
    if not last_versions:
        return []

    cache_key = (ecosystem, package_name)
    if cache_key not in latest_cache:
        latest_cache[cache_key] = fetch_latest_version(ecosystem, package_name)
    latest = latest_cache[cache_key]
    if latest is None:
        return []

    # 全ての last_affected より新しい場合のみ（一部の範囲だけ超えていても確信は持てない）
    if all(is_newer_version(latest, last) for last in last_versions):
        return [latest]
    return []


class FindingBuilder:
    """パッケージ×バージョンの OSV 照合結果から、DependencyFinding レコード辞書を構築する。

    OSV の脆弱性詳細（複数パッケージが同じ ID を参照しうる）とレジストリの最新版
    （修正版の補完用）は、同じ実行内で何度も引かないようインスタンスにキャッシュする。
    """

    def __init__(self, repo_visibility: dict[str, str] | None = None) -> None:
        self._repo_visibility = repo_visibility or {}
        self._vuln_cache: dict[str, dict[str, Any] | None] = {}
        self._latest_cache: dict[tuple[str, str], str | None] = {}

    def _get_vuln(self, osv_id: str) -> dict[str, Any] | None:
        """脆弱性詳細を取得する（キャッシュ付き。取得失敗は None として記録し再取得しない）。"""
        if osv_id not in self._vuln_cache:
            try:
                self._vuln_cache[osv_id] = fetch_vuln_by_id(osv_id)
            except httpx.HTTPError as exc:
                logger.warning("Failed to fetch vuln %s: %s", osv_id, exc)
                self._vuln_cache[osv_id] = None
        return self._vuln_cache[osv_id]

    def _fixed_versions(
        self, vuln: dict[str, Any], ecosystem: str, package_name: str,
    ) -> list[str]:
        """OSV の `fixed` を集める。無ければレジストリの最新版から補完を試みる。"""
        fixed_versions = sorted({
            event["fixed"]
            for affected in vuln.get("affected", [])
            for rng in affected.get("ranges", [])
            for event in rng.get("events", [])
            if "fixed" in event
        })
        if fixed_versions:
            return fixed_versions
        return _infer_fixed_versions(vuln, ecosystem, package_name, self._latest_cache)

    @staticmethod
    def _cve_ids(vuln: dict[str, Any]) -> list[str]:
        """aliases から CVE 形式のみ抽出する。

        OSV ID だけでは CVE と直接対応しないため保存しておく
        （Issue #135: KEV 掲載有無・EPSS スコアとの突合に使う）。
        """
        return sorted({alias for alias in vuln.get("aliases", []) if alias.startswith("CVE-")})

    def build(self, dep_to_repos: dict[DepKey, list[tuple[str, str]]]) -> list[dict[str, Any]]:
        """パッケージ×バージョンを OSV に照合し、検知レコード辞書のリストを返す。"""
        hits = query_versions_batch(list(dep_to_repos.keys()))
        if not hits:
            return []

        records: list[dict[str, Any]] = []
        now = now_utc()

        for key, osv_ids in hits.items():
            ecosystem, package_name, version = key
            for osv_id in osv_ids:
                vuln = self._get_vuln(osv_id)
                if vuln is None:
                    continue

                severity, cvss_score = parse_severity(vuln)
                shared = {
                    "ecosystem": ecosystem,
                    "package_name": package_name,
                    "installed_version": version,
                    "osv_id": osv_id,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "summary": (vuln.get("summary") or "").strip(),
                    "fixed_versions": self._fixed_versions(vuln, ecosystem, package_name),
                    "cve_ids": self._cve_ids(vuln),
                    # apply_reachability が上書きする。呼び出し自体が失敗した場合の
                    # フォールバック値として "unknown" を既定にしておく
                    "reachability": "unknown",
                    "detected_at": now,
                }
                for repo_full_name, manifest_path in dep_to_repos[key]:
                    records.append({
                        **shared,
                        "repo_full_name": repo_full_name,
                        "manifest_path": manifest_path,
                        "repo_visibility": self._repo_visibility.get(repo_full_name),
                    })

        return records


def build_findings(
    dep_to_repos: dict[DepKey, list[tuple[str, str]]],
    repo_visibility: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """パッケージ×バージョンを OSV に照合し、DependencyFinding レコード辞書のリストを構築する。"""
    return FindingBuilder(repo_visibility).build(dep_to_repos)
