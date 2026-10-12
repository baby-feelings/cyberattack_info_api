"""検知レコードへの到達可能性（import レベル）の付与。

判定そのもの（`reachability.check_reachability`）は GitHub に触れない純粋な解析。ここは、対象
リポジトリのソースを取得して判定を呼び、結果をレコードに載せる（GitHub 通信を伴う側）。
"""
import logging
from typing import Any

import httpx

from app.core.github.accounts import list_target_repos
from app.core.github.repo import GitHubRepo
from app.depscan.reachability import SOURCE_EXTENSIONS, check_reachability
from app.depscan.source_files import collect_source_files

logger = logging.getLogger(__name__)


def apply_reachability(
    records: list[dict[str, Any]], username: str, token: str,
) -> None:
    """検知レコードに到達可能性（import レベル）を付与する（records を in-place 更新）。

    リポジトリ×エコシステム単位でソースファイルを1回だけ取得し、同じリポジトリの
    複数レコードで使い回す（GitHub API 呼び出し削減）。取得失敗時は "unknown" のまま
    据え置き、DEPSCAN 全体は失敗させない。
    """
    if not records:
        return

    by_repo: dict[str, set[str]] = {}
    for rec in records:
        by_repo.setdefault(rec["repo_full_name"], set()).add(rec["ecosystem"])

    branch_map = {
        repo_info["full_name"]: repo_info.get("default_branch") or "main"
        for repo_info in list_target_repos(username, token)
    }

    source_cache: dict[tuple[str, str], dict[str, str]] = {}
    for full_name, ecosystems in by_repo.items():
        repo = GitHubRepo.from_full_name(full_name, token)
        default_branch = branch_map.get(full_name, "main")
        for ecosystem in ecosystems:
            extensions = SOURCE_EXTENSIONS.get(ecosystem)
            if extensions is None:
                continue
            try:
                source_cache[(full_name, ecosystem)] = collect_source_files(
                    repo, default_branch, extensions,
                )
            except httpx.HTTPError as exc:
                logger.warning(
                    "Reachability: failed to fetch source for %s (%s): %s",
                    full_name, ecosystem, exc,
                )

    for rec in records:
        source_files = source_cache.get((rec["repo_full_name"], rec["ecosystem"]))
        if source_files is None:
            continue  # 取得失敗・対象外エコシステム: "unknown" のまま据え置く
        rec["reachability"] = check_reachability(
            rec["ecosystem"], rec["package_name"], source_files,
        )
