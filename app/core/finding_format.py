"""依存ライブラリ脆弱性検知結果（DependencyFinding 相当）の共通整形ロジック。

Slack 通知（app.core.notifications）と GitHub Issue 自動起票（app.depscan.crawler）の
両方から、同じ「パッケージ単位に集約した見やすい行」を再利用するために切り出す。
"""
from typing import Any

# 重大度の表示順（数値が小さいほど深刻。未知の値は最後に回す）
_SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def severity_rank(severity: str | None) -> int:
    """重大度文字列を表示順のランクに変換する（数値が小さいほど深刻）。"""
    return _SEVERITY_ORDER.get((severity or "UNKNOWN").upper(), len(_SEVERITY_ORDER))


def format_package_lines(findings: list[dict[str, Any]]) -> list[str]:
    """1リポジトリ分の findings を (パッケージ名, インストール済みバージョン) 単位で
    1行に集約し、重大度が高い順に整形する。

    同一パッケージに複数の CVE がある場合、内訳を「CRITICAL×1, HIGH×2」のように
    件数でまとめ、修正済みバージョンは重複を除いて列挙する。
    """
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for finding in findings:
        key = (finding["package_name"], finding["installed_version"])
        groups.setdefault(key, []).append(finding)

    def group_sort_key(key: tuple[str, str]) -> tuple[int, str]:
        best_rank = min(severity_rank(f.get("severity")) for f in groups[key])
        return (best_rank, key[0])

    lines = []
    for package_name, installed_version in sorted(groups, key=group_sort_key):
        group = groups[(package_name, installed_version)]

        sev_counts: dict[str, int] = {}
        for finding in group:
            sev = (finding.get("severity") or "UNKNOWN").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        sev_summary = ", ".join(
            f"{sev}×{count}"
            for sev, count in sorted(sev_counts.items(), key=lambda kv: severity_rank(kv[0]))
        )

        fixed_versions = sorted({
            v for f in group for v in (f.get("fixed_versions") or [])
        })
        fix = ", ".join(fixed_versions) if fixed_versions else "未提供"

        lines.append(
            f"• {package_name} {installed_version} — {sev_summary}"
            f"（計{len(group)}件）→ 修正版: {fix}"
        )

    return lines
