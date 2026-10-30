"""GitHub のセキュリティアラートの取得と、共通の形への変換（Issue #402）。

取得は、リポジトリ単位の `GitHubRepo`（認証・リトライ済みの API）を使う。機能が無効なリポジトリ・
権限が無いトークンは、404・403 になる。これらは「取得不可」として呼び出し側に None で伝える
（アラートが 0 件であることと区別する。0 件と見なすと、既存のアラートを
「解決済み」にしてしまうため）。

【重要・セキュリティ】secret scanning のアラートの応答には、シークレットの値（`secret`）が含まれる。
`normalize_secret` は、この値を一切参照しない（種類・有効性・公開状況だけを使う）。
"""
import logging
from datetime import datetime
from typing import Any

import httpx

from app.core.github.repo import GitHubRepo
from app.crawler_logs.writer import now_utc
from app.github_alerts.models import KIND_CODE, KIND_DEPENDABOT, KIND_SECRET

logger = logging.getLogger(__name__)

_PER_PAGE = 100
# 1リポジトリ・1種類あたりに読むページ数の上限（過剰な API 呼び出しを防ぐ安全弁）
_MAX_PAGES = 10

# 種類ごとの、API のパス（リポジトリ配下）
_PATHS = {
    KIND_SECRET: "/secret-scanning/alerts",
    KIND_DEPENDABOT: "/dependabot/alerts",
    KIND_CODE: "/code-scanning/alerts",
}


def _parse_time(value: str | None) -> datetime:
    """GitHub の ISO 8601（末尾 Z）を、tz つきの datetime にする（無ければ、現在）。"""
    if not value:
        return now_utc()
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _upper(value: Any) -> str | None:
    return str(value).upper() if value else None


def normalize_secret(repo_full_name: str, item: dict[str, Any]) -> dict[str, Any]:
    """secret scanning のアラートを共通の形にする（シークレットの値は、参照しない）。"""
    validity = item.get("validity") or "unknown"
    # 有効（まだ使える）なシークレットは、すぐに無効化が必要なため CRITICAL
    severity = "CRITICAL" if validity == "active" else "HIGH"
    name = item.get("secret_type_display_name") or item.get("secret_type") or "secret"
    return {
        "kind": KIND_SECRET, "repo_full_name": repo_full_name, "number": item["number"],
        "severity": severity, "title": f"{name}（有効性: {validity}）",
        "html_url": item["html_url"],
        "detail": {
            "secret_type": item.get("secret_type"), "validity": validity,
            "publicly_leaked": bool(item.get("publicly_leaked")),
            "push_protection_bypassed": bool(item.get("push_protection_bypassed")),
        },
        "detected_at": _parse_time(item.get("created_at")),
    }


def normalize_dependabot(repo_full_name: str, item: dict[str, Any]) -> dict[str, Any]:
    """Dependabot alerts のアラートを共通の形にする。"""
    dependency = (item.get("dependency") or {}).get("package") or {}
    advisory = item.get("security_advisory") or {}
    patched = (item.get("security_vulnerability") or {}).get("first_patched_version") or {}
    return {
        "kind": KIND_DEPENDABOT, "repo_full_name": repo_full_name, "number": item["number"],
        "severity": _upper(advisory.get("severity")),
        "title": advisory.get("summary") or dependency.get("name") or "dependabot alert",
        "html_url": item["html_url"],
        "detail": {
            "ecosystem": dependency.get("ecosystem"), "package": dependency.get("name"),
            "ghsa_id": advisory.get("ghsa_id"), "cve_id": advisory.get("cve_id"),
            "fixed_version": patched.get("identifier"),
        },
        "detected_at": _parse_time(item.get("created_at")),
    }


def normalize_code(repo_full_name: str, item: dict[str, Any]) -> dict[str, Any]:
    """code scanning のアラートを共通の形にする。"""
    rule = item.get("rule") or {}
    location = ((item.get("most_recent_instance") or {}).get("location")) or {}
    return {
        "kind": KIND_CODE, "repo_full_name": repo_full_name, "number": item["number"],
        "severity": _upper(rule.get("security_severity_level") or rule.get("severity")),
        "title": rule.get("description") or rule.get("id") or "code scanning alert",
        "html_url": item["html_url"],
        "detail": {
            "rule_id": rule.get("id"), "path": location.get("path"),
            "tool": (item.get("tool") or {}).get("name"),
        },
        "detected_at": _parse_time(item.get("created_at")),
    }


_NORMALIZERS = {
    KIND_SECRET: normalize_secret, KIND_DEPENDABOT: normalize_dependabot, KIND_CODE: normalize_code,
}


def fetch_alerts(repo: GitHubRepo, kind: str) -> tuple[list[dict[str, Any]] | None, str | None]:
    """1リポジトリ・1種類の、未解決（open）のアラートを取得する。

    Returns:
        (アラート, 取得不可の理由)。取得できたときは (リスト, None)、機能が無効・権限不足
        （403・404）のときは (None, 理由)。それ以外の失敗（5xx・通信）は、例外で伝える。
    """
    normalize = _NORMALIZERS[kind]
    alerts: list[dict[str, Any]] = []
    with repo.api() as api:
        for page in range(1, _MAX_PAGES + 1):
            response = api.get(
                repo.path(_PATHS[kind]),
                params={"state": "open", "per_page": _PER_PAGE, "page": page},
            )
            if response.status_code in (403, 404):
                return None, f"機能が無効、または権限がありません（HTTP {response.status_code}）"
            response.raise_for_status()
            items = response.json()
            alerts.extend(normalize(repo.full_name, item) for item in items)
            if len(items) < _PER_PAGE:
                break
    return alerts, None


def is_unavailable_error(exc: Exception) -> bool:
    """通信の失敗か（呼び出し側が、そのリポジトリを飛ばして続けるための判定）。"""
    return isinstance(exc, httpx.HTTPError)
