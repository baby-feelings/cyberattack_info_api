"""全対象リポジトリからのロックファイルの収集とパース（DEPSCAN）。"""
import logging

import httpx

from app.core.github.accounts import list_target_repos
from app.core.github.repo import GitHubRepo
from app.depscan.parsers import LOCKFILE_FILENAMES, parse_manifest

logger = logging.getLogger(__name__)

# (ecosystem, package_name, version) キー型のエイリアス
DepKey = tuple[str, str, str]


def discover_manifests(repo: GitHubRepo, default_branch: str) -> list[str]:
    """リポジトリ内の対応ロックファイルのパス一覧を返す（サブディレクトリ含む）。"""
    try:
        paths = repo.tree(default_branch)
    except httpx.HTTPError as exc:
        logger.warning("Failed to get tree for %s: %s", repo.full_name, exc)
        return []
    return [p for p in paths if p.rsplit("/", 1)[-1] in LOCKFILE_FILENAMES]


def collect_dependencies(
    token: str,
) -> tuple[dict[DepKey, list[tuple[str, str]]], int, dict[str, str]]:
    """全対象リポジトリからロックファイルを収集・パースする。

    Returns:
        (
            {(ecosystem, package_name, version): [(repo_full_name, manifest_path), ...]},
            スキャンしたリポジトリ数,
            {repo_full_name: "public"/"private"}（Issue #131: 資産コンテキストのrepo_visibility用。
            GitHub APIの"private"フィールドから導出する）,
        )
    """
    dep_to_repos: dict[DepKey, list[tuple[str, str]]] = {}
    repos = list_target_repos(token)
    logger.info("DEPSCAN: %d target repos to scan", len(repos))

    repo_visibility: dict[str, str] = {
        repo_info["full_name"]: "private" if repo_info.get("private") else "public"
        for repo_info in repos
    }

    for i, repo_info in enumerate(repos, start=1):
        full_name = repo_info["full_name"]
        repo = GitHubRepo.from_full_name(full_name, token)
        default_branch = repo_info.get("default_branch") or "main"
        logger.info("DEPSCAN: [%d/%d] scanning %s", i, len(repos), full_name)

        manifest_paths = discover_manifests(repo, default_branch)
        if manifest_paths:
            logger.info(
                "DEPSCAN: [%d/%d] %s: %d manifest(s) found: %s",
                i, len(repos), full_name, len(manifest_paths), manifest_paths,
            )

        for path in manifest_paths:
            filename = path.rsplit("/", 1)[-1]
            try:
                content = repo.file_content(path)
            except httpx.HTTPError as exc:
                logger.warning("Failed to fetch %s in %s: %s", path, full_name, exc)
                continue

            for ref in parse_manifest(filename, content):
                key = (ref.ecosystem, ref.name, ref.version)
                dep_to_repos.setdefault(key, []).append((full_name, path))

    logger.info("DEPSCAN: repo scan complete, %d unique dependencies found", len(dep_to_repos))
    return dep_to_repos, len(repos), repo_visibility
