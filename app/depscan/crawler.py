"""依存ライブラリ脆弱性スキャナー（DEPSCAN）モジュール。

GitHub 上の自作アプリ全リポジトリのロックファイルを取得・パースし、
OSV API とリアルタイム照合して脆弱な依存パッケージを検知する。
検知結果は DependencyFinding テーブルに保存し、新規分のみ Slack 通知する。
APScheduler から毎日呼び出される。
"""
import logging
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.finding_format import format_package_lines
from app.core.notifications import (
    DASHBOARD_URL,
    notify_dependency_findings,
    notify_error,
)
from app.core.osv_client import fetch_vuln_by_id, parse_severity, query_versions_batch
from app.crawler_logs.writer import now_utc, write_crawler_log
from app.depscan.github_client import (
    add_issue_comment,
    create_issue,
    find_open_issue,
    get_file_content,
    get_repo_tree,
    list_target_repos,
)
from app.depscan.models import DependencyFinding
from app.depscan.parsers import LOCKFILE_FILENAMES, parse_manifest

logger = logging.getLogger(__name__)

# (repo_full_name, ecosystem, package_name, osv_id) キー型のエイリアス
FindingKey = tuple[str, str, str, str]
# (ecosystem, package_name, version) キー型のエイリアス
DepKey = tuple[str, str, str]

# GitHub Issue自動起票時のタイトル（Open Issue検索の一致キーも兼ねる）
_ISSUE_TITLE = "🚨 依存ライブラリの脆弱性が検出されました (DEPSCAN)"


def _discover_manifests(owner: str, repo: str, default_branch: str, token: str) -> list[str]:
    """リポジトリ内の対応ロックファイルのパス一覧を返す（サブディレクトリ含む）。"""
    try:
        paths = get_repo_tree(owner, repo, default_branch, token)
    except httpx.HTTPError as exc:
        logger.warning("Failed to get tree for %s/%s: %s", owner, repo, exc)
        return []
    return [p for p in paths if p.rsplit("/", 1)[-1] in LOCKFILE_FILENAMES]


def _collect_dependencies(
    username: str, token: str,
) -> tuple[dict[DepKey, list[tuple[str, str]]], int]:
    """全対象リポジトリからロックファイルを収集・パースする。

    Returns:
        (
            {(ecosystem, package_name, version): [(repo_full_name, manifest_path), ...]},
            スキャンしたリポジトリ数,
        )
    """
    dep_to_repos: dict[DepKey, list[tuple[str, str]]] = {}
    repos = list_target_repos(username, token)
    logger.info("DEPSCAN: %d target repos to scan", len(repos))

    for i, repo_info in enumerate(repos, start=1):
        full_name = repo_info["full_name"]
        owner, repo = full_name.split("/", 1)
        default_branch = repo_info.get("default_branch") or "main"
        logger.info("DEPSCAN: [%d/%d] scanning %s", i, len(repos), full_name)

        manifest_paths = _discover_manifests(owner, repo, default_branch, token)
        if manifest_paths:
            logger.info(
                "DEPSCAN: [%d/%d] %s: %d manifest(s) found: %s",
                i, len(repos), full_name, len(manifest_paths), manifest_paths,
            )

        for path in manifest_paths:
            filename = path.rsplit("/", 1)[-1]
            try:
                content = get_file_content(owner, repo, path, token)
            except httpx.HTTPError as exc:
                logger.warning("Failed to fetch %s in %s: %s", path, full_name, exc)
                continue

            for ref in parse_manifest(filename, content):
                key = (ref.ecosystem, ref.name, ref.version)
                dep_to_repos.setdefault(key, []).append((full_name, path))

    logger.info("DEPSCAN: repo scan complete, %d unique dependencies found", len(dep_to_repos))
    return dep_to_repos, len(repos)


def _build_findings(
    dep_to_repos: dict[DepKey, list[tuple[str, str]]],
) -> list[dict[str, Any]]:
    """パッケージ×バージョンを OSV に照合し、DependencyFinding レコード辞書のリストを構築する。"""
    hits = query_versions_batch(list(dep_to_repos.keys()))
    if not hits:
        return []

    # 脆弱性 ID ごとの詳細情報をキャッシュ（複数パッケージが同じ脆弱性 ID を参照しうる）
    vuln_cache: dict[str, dict[str, Any] | None] = {}
    records: list[dict[str, Any]] = []
    now = now_utc()

    for key, osv_ids in hits.items():
        ecosystem, package_name, version = key
        for osv_id in osv_ids:
            if osv_id not in vuln_cache:
                try:
                    vuln_cache[osv_id] = fetch_vuln_by_id(osv_id)
                except httpx.HTTPError as exc:
                    logger.warning("Failed to fetch vuln %s: %s", osv_id, exc)
                    vuln_cache[osv_id] = None
            vuln = vuln_cache[osv_id]
            if vuln is None:
                continue

            severity, cvss_score = parse_severity(vuln)
            summary = (vuln.get("summary") or "").strip()
            fixed_versions = sorted({
                event["fixed"]
                for affected in vuln.get("affected", [])
                for rng in affected.get("ranges", [])
                for event in rng.get("events", [])
                if "fixed" in event
            })

            for repo_full_name, manifest_path in dep_to_repos[key]:
                records.append({
                    "repo_full_name": repo_full_name,
                    "ecosystem": ecosystem,
                    "package_name": package_name,
                    "installed_version": version,
                    "osv_id": osv_id,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "summary": summary,
                    "fixed_versions": fixed_versions,
                    "manifest_path": manifest_path,
                    "detected_at": now,
                })

    return records


def _upsert_findings(
    db: Session, records: list[dict[str, Any]],
) -> tuple[int, list[dict[str, Any]]]:
    """DependencyFinding を Upsert する。

    Returns:
        (新規挿入件数, 新規挿入されたレコードのスナップショット辞書リスト)
        スナップショットは Slack 通知用（DB セッションクローズ後の
        DetachedInstanceError を避けるため ORM オブジェクトではなく辞書で返す）
    """
    inserted = 0
    new_snapshots: list[dict[str, Any]] = []
    seen_keys: set[FindingKey] = set()

    for rec in records:
        key: FindingKey = (
            rec["repo_full_name"], rec["ecosystem"], rec["package_name"], rec["osv_id"],
        )
        if key in seen_keys:
            continue
        seen_keys.add(key)

        existing = (
            db.query(DependencyFinding)
            .filter(
                DependencyFinding.repo_full_name == rec["repo_full_name"],
                DependencyFinding.ecosystem == rec["ecosystem"],
                DependencyFinding.package_name == rec["package_name"],
                DependencyFinding.osv_id == rec["osv_id"],
            )
            .first()
        )

        if existing is None:
            db.add(DependencyFinding(**rec))
            inserted += 1
            new_snapshots.append(rec)
        elif existing.resolved_at is not None:
            # 一度解決した後に再発したケース：解決フラグを解除して情報を更新
            for field, value in rec.items():
                setattr(existing, field, value)
            existing.resolved_at = None

    db.commit()
    return inserted, new_snapshots


def _resolve_stale_findings(
    db: Session, current_keys: set[FindingKey], repo_owner_prefix: str | None = None,
) -> int:
    """今回のスキャンで検知されなくなった未解決 Finding を解決済みにする。

    Args:
        repo_owner_prefix: 指定した場合、`"{prefix}/"` から始まるリポジトリのみを
            対象にする（オンデマンドの個人スキャンが、無関係な他リポジトリの
            未解決レコードまで誤って解決済みにしてしまわないようにするため）。
    """
    resolved = 0
    now = now_utc()
    query = db.query(DependencyFinding).filter(DependencyFinding.resolved_at.is_(None))
    if repo_owner_prefix is not None:
        query = query.filter(DependencyFinding.repo_full_name.like(f"{repo_owner_prefix}/%"))
    open_findings = query.all()
    for finding in open_findings:
        key: FindingKey = (
            finding.repo_full_name, finding.ecosystem, finding.package_name, finding.osv_id,
        )
        if key not in current_keys:
            finding.resolved_at = now
            resolved += 1
    db.commit()
    return resolved


def _file_github_issues(new_snapshots: list[dict[str, Any]]) -> None:
    """新規検知を、検知されたリポジトリ自身に GitHub Issue として自動起票する。

    同名の Open な Issue が既にあればコメントを追記し、無ければ新規作成する。
    GitHub API 呼び出しが失敗しても（Issues 書き込み権限が無いトークン等）、
    DEPSCAN 全体の成功を妨げないようリポジトリ単位で例外を握りつぶす。
    """
    if not new_snapshots:
        return

    by_repo: dict[str, list[dict[str, Any]]] = {}
    for finding in new_snapshots:
        by_repo.setdefault(finding["repo_full_name"], []).append(finding)

    timestamp = now_utc().strftime("%Y-%m-%d %H:%M UTC")
    token = settings.GITHUB_TOKEN

    for full_name, findings in by_repo.items():
        owner, repo = full_name.split("/", 1)
        body = (
            f"DEPSCAN が依存ライブラリの脆弱性を検知しました（{timestamp}）。\n\n"
            + "\n".join(format_package_lines(findings))
            + f"\n\n---\n詳細: {DASHBOARD_URL}"
        )
        try:
            issue_number = find_open_issue(owner, repo, _ISSUE_TITLE, token)
            if issue_number is not None:
                add_issue_comment(owner, repo, issue_number, body, token)
                logger.info(
                    "DEPSCAN: added comment to existing issue #%d in %s", issue_number, full_name,
                )
            else:
                issue = create_issue(owner, repo, _ISSUE_TITLE, body, token)
                logger.info("DEPSCAN: created issue #%s in %s", issue.get("number"), full_name)
        except httpx.HTTPError as exc:
            logger.warning("DEPSCAN: failed to file GitHub issue for %s: %s", full_name, exc)


def fetch_and_scan_dependencies() -> tuple[int, int, int]:
    """DEPSCAN のメインエントリポイント。

    GitHub 上の全対象リポジトリのロックファイルを収集し、OSV API と照合して
    脆弱な依存パッケージを検知する。結果は crawler_logs に記録し、
    新規検知があれば Slack に通知する。APScheduler から毎日呼び出される。

    Returns:
        (new_findings, resolved, repos_scanned) のタプル
    """
    logger.info("=== DEPSCAN started ===")
    started_at = now_utc()
    new_count = 0
    resolved_count = 0
    repos_scanned = 0
    new_snapshots: list[dict[str, Any]] = []

    db: Session = SessionLocal()
    try:
        dep_to_repos, repos_scanned = _collect_dependencies(
            settings.GITHUB_USERNAME, settings.GITHUB_TOKEN,
        )
        logger.info(
            "DEPSCAN: %d repos scanned, %d unique (ecosystem,package,version) found",
            repos_scanned, len(dep_to_repos),
        )

        records = _build_findings(dep_to_repos)
        new_count, new_snapshots = _upsert_findings(db, records)

        current_keys: set[FindingKey] = {
            (r["repo_full_name"], r["ecosystem"], r["package_name"], r["osv_id"])
            for r in records
        }
        resolved_count = _resolve_stale_findings(db, current_keys)

    except Exception as exc:
        write_crawler_log(
            crawler_type="DEPSCAN",
            status="error",
            started_at=started_at,
            finished_at=now_utc(),
            inserted=new_count,
            updated=0,
            deleted=resolved_count,
            error_message=str(exc),
        )
        notify_error("DEPSCAN", str(exc))
        raise
    finally:
        db.close()

    logger.info(
        "=== DEPSCAN completed: new=%d, resolved=%d, repos=%d ===",
        new_count, resolved_count, repos_scanned,
    )
    write_crawler_log(
        crawler_type="DEPSCAN",
        status="success",
        started_at=started_at,
        finished_at=now_utc(),
        inserted=new_count,
        updated=0,
        deleted=resolved_count,
    )
    notify_dependency_findings(new_snapshots)
    _file_github_issues(new_snapshots)
    return new_count, resolved_count, repos_scanned
