"""依存ライブラリ脆弱性検知結果（DependencyFinding 相当）の共通整形ロジック。

Slack 通知（app.core.notifications.dependency_findings）と
GitHub Issue 自動起票（app.depscan.issue_management）の両方から、同じ「パッケージ単位に集約した
見やすい行」を再利用するために切り出す。
"""
from typing import Any

from app.core.osv_client import is_malicious_advisory

# 重大度の表示順（数値が小さいほど深刻。未知の値は最後に回す）
_SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def severity_rank(severity: str | None) -> int:
    """重大度文字列を表示順のランクに変換する（数値が小さいほど深刻）。"""
    return _SEVERITY_ORDER.get((severity or "UNKNOWN").upper(), len(_SEVERITY_ORDER))


# 悪意あるパッケージを検知したときの対応手順（Slack通知とGitHub Issueの両方に載せる）
MALICIOUS_RESPONSE_STEPS: tuple[str, ...] = (
    "1. 該当バージョンを依存から削除する（更新ではなく削除。正規の別パッケージへ置き換える）",
    "2. ロックファイルを再生成し、`node_modules`・仮想環境・キャッシュを破棄して入れ直す",
    "3. そのパッケージを実行した環境（開発PC・CI・本番）の認証情報（トークン・APIキー・SSH鍵）を、"
    "漏えいしたものとみなして再発行する",
    "4. CIのログ・不審なコミット・見慣れないデプロイキーやWebhookが無いかを確認する",
)


def is_malicious_finding(finding: dict[str, Any]) -> bool:
    """検知レコード（辞書）が、悪意あるパッケージ（OSV `MAL-*`）のものか。"""
    return is_malicious_advisory(finding.get("osv_id") or "")


def split_malicious(
    findings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """検知を（悪意あるパッケージ, それ以外）に分ける。"""
    malicious = [f for f in findings if is_malicious_finding(f)]
    others = [f for f in findings if not is_malicious_finding(f)]
    return malicious, others


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

        # 悪意あるパッケージは「修正版」ではなく「削除」が対応のため、行頭で区別する
        mark = "🛑 悪意あるパッケージ: " if any(is_malicious_finding(f) for f in group) else ""
        lines.append(
            f"• {mark}{package_name} {installed_version} — {sev_summary}"
            f"（計{len(group)}件）→ 修正版: {fix}"
        )

    return lines


def format_malicious_section(findings: list[dict[str, Any]]) -> list[str]:
    """悪意あるパッケージの検知と対応手順の節（Slack通知・GitHub Issue共通）。

    `findings` は悪意あるパッケージの検知のみ（呼び出し側で `split_malicious` する）。
    """
    return [
        "🛑 *悪意あるパッケージを検知しました（脆弱性ではなくマルウェアです）*",
        *format_package_lines(findings),
        "",
        "*対応手順*",
        *MALICIOUS_RESPONSE_STEPS,
    ]
