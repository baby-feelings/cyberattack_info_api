"""点検する公開サイトの URL の決定（リポジトリの情報から自動検出＋設定で追加）。

自分の所有するドメインだけが対象。次の3つから集める（重複は除く）。

1. リポジトリの Homepage 欄
2. Firebase Hosting（`.firebaserc` の全環境のプロジェクト ID → `https://<id>.web.app`）と、
   Firestore の確認先
3. GitHub Pages（`has_pages` のリポジトリ → `https://<owner>.github.io[/<repo>]`）

設定 `EXTERNAL_MONITOR_URLS`（カンマ区切り。`URL=owner/repo` で所有リポジトリに紐づけられる）で、
足りないものを明示的に追加できる。
https 以外・IP アドレスの直接指定・内部アドレスは、`probes.is_safe_target` が、点検の直前に除く。
"""
import json
import logging
import re
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


@dataclass(frozen=True)
class ConfiguredEntry:
    """設定 `EXTERNAL_MONITOR_URLS` の1件（URL と、紐づける所有リポジトリ〈無ければ None〉）。"""

    url: str
    repo_full_name: str | None = None


_REPO_FULL_NAME = re.compile(r"^[\w.-]+/[\w.-]+$")


def parse_configured(raw: str) -> list[ConfiguredEntry]:
    """設定 `EXTERNAL_MONITOR_URLS`（カンマ区切り）を読む。

    各項目は `URL` または `URL=owner/repo`。リポジトリを付けると、そのリポジトリの所有者の画面
    （運用画面）に出る（付けないと、管理者の API キーでしか見えない）。形式が違うリポジトリは、
    付けない（URL だけ、点検する）。
    """
    entries: list[ConfiguredEntry] = []
    for item in raw.split(","):
        url, _, repo = item.strip().partition("=")
        url, repo = url.strip(), repo.strip()
        if not url:
            continue
        entries.append(ConfiguredEntry(url, repo if _REPO_FULL_NAME.match(repo) else None))
    return entries


def firebase_project_ids(firebaserc_text: str) -> list[str]:
    """`.firebaserc` の、すべての環境（開発・本番など）のプロジェクト ID（既定が先頭。重複は除く）。

    既定の1つだけを見ると、本番用のサイトが外形監視から漏れる（開発用が既定のことが多い）。
    """
    try:
        projects = (json.loads(firebaserc_text).get("projects") or {})
    except (ValueError, AttributeError):
        return []
    ordered = [projects.get("default"), *projects.values()]
    ids: list[str] = []
    for project in ordered:
        if project and str(project) not in ids:
            ids.append(str(project))
    return ids


def firebase_project_id(firebaserc_text: str) -> str | None:
    """`.firebaserc` の既定プロジェクト ID（無ければ、最初のもの）。"""
    ids = firebase_project_ids(firebaserc_text)
    return ids[0] if ids else None


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
        for project in _firebase_projects(GitHubRepo.from_full_name(full_name, token)):
            add(Target(f"https://{project}.web.app", SOURCE_FIREBASE, full_name, project))
    for entry in parse_configured(settings.EXTERNAL_MONITOR_URLS):
        # `<id>.web.app` は Firebase Hosting。Firestore の確認先（プロジェクト ID）も付ける
        host = urlsplit(entry.url).hostname or ""
        site_project = host.removesuffix(".web.app") if host.endswith(".web.app") else None
        add(Target(entry.url, SOURCE_CONFIG, entry.repo_full_name, site_project))
    return list(targets.values())


def _firebase_projects(repo: GitHubRepo) -> list[str]:
    """リポジトリの `.firebaserc` から、Firebase のプロジェクト ID をすべて読む（無ければ空）。"""
    try:
        return firebase_project_ids(repo.file_content(".firebaserc"))
    except httpx.HTTPError:
        return []
