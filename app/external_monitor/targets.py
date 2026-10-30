"""点検する公開サイトの URL の決定（リポジトリの情報から自動検出＋設定で追加）。

自分の所有するドメインだけが対象。次の3つから集める（重複は除く）。

1. リポジトリの Homepage 欄
2. Firebase Hosting（`.firebaserc` のプロジェクト ID → `https://<id>.web.app`）と、
   Firestore の確認先
3. GitHub Pages（`has_pages` のリポジトリ → `https://<owner>.github.io[/<repo>]`）

設定 `EXTERNAL_MONITOR_URLS`（カンマ区切り）で、足りないものを明示的に追加できる。
https 以外・IP アドレスの直接指定・内部アドレスは、`probes.is_safe_target` が、点検の直前に除く。
"""
import json
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from app.core.config import settings
from app.core.github.repo import GitHubRepo

logger = logging.getLogger(__name__)

SOURCE_HOMEPAGE = "homepage"
SOURCE_FIREBASE = "firebase"
SOURCE_PAGES = "github_pages"
SOURCE_CONFIG = "config"


@dataclass(frozen=True)
class Target:
    """点検する公開サイト1件。"""

    url: str
    source: str
    repo_full_name: str | None = None
    # Firebase のプロジェクト ID（Firestore の確認先。無ければ None）
    firebase_project: str | None = None


def normalize_url(url: str) -> str | None:
    """点検用に、https の URL を「スキーム＋ホスト（＋ポート）」の形に整える（それ以外は None）。

    パスは点検に使わない（トップページと、決まったパスだけを見る）。
    """
    parts = urlsplit(url.strip())
    if parts.scheme != "https" or not parts.hostname:
        return None
    return f"https://{parts.netloc}"


def configured_urls() -> list[str]:
    """設定 `EXTERNAL_MONITOR_URLS`（カンマ区切り）の URL。"""
    return [u.strip() for u in settings.EXTERNAL_MONITOR_URLS.split(",") if u.strip()]


def firebase_project_id(firebaserc_text: str) -> str | None:
    """`.firebaserc` の既定プロジェクト ID。"""
    try:
        projects = (json.loads(firebaserc_text).get("projects") or {})
    except (ValueError, AttributeError):
        return None
    project = projects.get("default") or next(iter(projects.values()), None)
    return str(project) if project else None


def discover_targets(repos: list[dict[str, Any]], token: str) -> list[Target]:
    """リポジトリの一覧から、点検する公開サイトを集める（URL の重複は除く）。"""
    targets: dict[str, Target] = {}

    def add(target: Target) -> None:
        normalized = normalize_url(target.url)
        if normalized and normalized not in targets:
            targets[normalized] = Target(
                normalized, target.source, target.repo_full_name, target.firebase_project,
            )

    for repo_info in repos:
        full_name = repo_info["full_name"]
        owner, _, name = full_name.partition("/")
        if repo_info.get("homepage"):
            add(Target(repo_info["homepage"], SOURCE_HOMEPAGE, full_name))
        if repo_info.get("has_pages"):
            # ユーザーのサイト（`<owner>.github.io`）は、ルート。それ以外は、`/<repo>` の下
            # （ホストは同じ）
            add(Target(f"https://{owner}.github.io", SOURCE_PAGES, full_name))
        project = _firebase_project(GitHubRepo.from_full_name(full_name, token))
        if project:
            add(Target(f"https://{project}.web.app", SOURCE_FIREBASE, full_name, project))
    for url in configured_urls():
        add(Target(url, SOURCE_CONFIG))
    return list(targets.values())


def _firebase_project(repo: GitHubRepo) -> str | None:
    """リポジトリの `.firebaserc` から、Firebase のプロジェクト ID を読む（無ければ None）。"""
    try:
        return firebase_project_id(repo.file_content(".firebaserc"))
    except httpx.HTTPError:
        return None
