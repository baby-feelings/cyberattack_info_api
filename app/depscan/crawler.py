"""依存ライブラリ脆弱性スキャナー（DEPSCAN）モジュール。

GitHub 上の自作アプリ全リポジトリのロックファイルを取得・パースし、
OSV API とリアルタイム照合して脆弱な依存パッケージを検知する。
検知結果は DependencyFinding テーブルに保存し、新規分のみ Slack 通知する。
APScheduler から毎日呼び出される。
"""
import logging
from datetime import timedelta
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal
from app.core.notifications import notify_dependency_findings, notify_error
from app.core.osv_client import fetch_vuln_by_id, parse_severity, query_versions_batch
from app.crawler_logs.writer import now_utc, write_crawler_log
from app.depscan.github_client import (
    get_file_content,
    get_repo_tree,
    get_source_files,
    list_target_repos,
)
from app.depscan.issue_management import _close_resolved_repo_issues, _file_github_issues
from app.depscan.models import DependencyFinding
from app.depscan.parsers import LOCKFILE_FILENAMES, parse_manifest
from app.depscan.reachability import SOURCE_EXTENSIONS, check_reachability

logger = logging.getLogger(__name__)

# (repo_full_name, ecosystem, package_name, osv_id) キー型のエイリアス
FindingKey = tuple[str, str, str, str]
# (ecosystem, package_name, version) キー型のエイリアス
DepKey = tuple[str, str, str]


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
    repos = list_target_repos(username, token)
    logger.info("DEPSCAN: %d target repos to scan", len(repos))

    repo_visibility: dict[str, str] = {
        repo_info["full_name"]: "private" if repo_info.get("private") else "public"
        for repo_info in repos
    }

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
    return dep_to_repos, len(repos), repo_visibility


def _build_findings(
    dep_to_repos: dict[DepKey, list[tuple[str, str]]],
    repo_visibility: dict[str, str] | None = None,
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
            # OSV IDだけではCVEと直接対応しないため、aliasesからCVE形式のみ抽出して
            # 保存しておく（Issue #135: KEV掲載有無・EPSSスコアとの突合に使う）
            cve_ids = sorted({
                alias for alias in vuln.get("aliases", [])
                if alias.startswith("CVE-")
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
                    "cve_ids": cve_ids,
                    "manifest_path": manifest_path,
                    # _apply_reachability が上書きする。呼び出し自体が失敗した場合の
                    # フォールバック値として "unknown" を既定にしておく
                    "reachability": "unknown",
                    "repo_visibility": (repo_visibility or {}).get(repo_full_name),
                    "detected_at": now,
                })

    return records


def _apply_reachability(
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
        owner, repo = full_name.split("/", 1)
        default_branch = branch_map.get(full_name, "main")
        for ecosystem in ecosystems:
            extensions = SOURCE_EXTENSIONS.get(ecosystem)
            if extensions is None:
                continue
            try:
                source_cache[(full_name, ecosystem)] = get_source_files(
                    owner, repo, default_branch, token, extensions,
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
        else:
            # 既存の未解決レコード: 到達可能性はソースコードの変化を反映するため、
            # repo_visibilityはリポジトリの公開設定変更を反映するため、cve_idsは
            # OSV側のalias追加を反映するため、毎回のスキャンで更新する
            # （他のフィールドは安定しているため更新しない）
            existing.reachability = rec.get("reachability")
            existing.repo_visibility = rec.get("repo_visibility")
            existing.cve_ids = rec.get("cve_ids", [])

    db.commit()
    return inserted, new_snapshots


def _resolve_stale_findings(
    db: Session, current_keys: set[FindingKey], repo_owner_prefix: str | None = None,
) -> tuple[int, set[str]]:
    """今回のスキャンで検知されなくなった未解決 Finding を解決済みにする。

    Args:
        repo_owner_prefix: 指定した場合、`"{prefix}/"` から始まるリポジトリのみを
            対象にする（オンデマンドの個人スキャンが、無関係な他リポジトリの
            未解決レコードまで誤って解決済みにしてしまわないようにするため）。

    Returns:
        (解決件数, 今回1件以上解決した repo_full_name の集合)。
        後者は _close_resolved_repo_issues が「Issue クローズ判定が必要な
        リポジトリ」を絞り込むために使う（何も解決していないリポジトリを
        毎回チェックする無駄を避けるため）。
    """
    resolved = 0
    affected_repos: set[str] = set()
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
            affected_repos.add(finding.repo_full_name)
    db.commit()
    return resolved, affected_repos


def _delete_old_depscan_records(db: Session) -> int:
    """保持期間（DEPSCAN_RETENTION_DAYS）を超えて解決済みのままの DEPSCAN レコードを削除する。

    resolved_at が cutoff より古い（=解決済みのまま長期間経過した）レコードのみを
    対象とする。未解決のレコードは対応が必要な情報のため、経過期間に関わらず削除しない。

    Returns:
        削除件数
    """
    cutoff = now_utc() - timedelta(days=settings.DEPSCAN_RETENTION_DAYS)
    deleted = (
        db.query(DependencyFinding)
        .filter(
            DependencyFinding.resolved_at.is_not(None),
            DependencyFinding.resolved_at < cutoff,
        )
        .delete(synchronize_session=False)
    )
    db.commit()
    logger.info("DEPSCAN old resolved records deleted: %d (resolved_at < %s)", deleted, cutoff)
    return deleted


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
    purged_count = 0
    repos_scanned = 0
    new_snapshots: list[dict[str, Any]] = []

    db: Session = SessionLocal()
    try:
        dep_to_repos, repos_scanned, repo_visibility = _collect_dependencies(
            settings.GITHUB_USERNAME, settings.GITHUB_TOKEN,
        )
        logger.info(
            "DEPSCAN: %d repos scanned, %d unique (ecosystem,package,version) found",
            repos_scanned, len(dep_to_repos),
        )

        records = _build_findings(dep_to_repos, repo_visibility)

        # 到達可能性の判定失敗はクロール全体を失敗させない（"unknown" のまま据え置く）
        try:
            _apply_reachability(records, settings.GITHUB_USERNAME, settings.GITHUB_TOKEN)
        except Exception as exc:
            logger.error("Failed to compute reachability: %s", exc, exc_info=True)

        new_count, new_snapshots = _upsert_findings(db, records)

        current_keys: set[FindingKey] = {
            (r["repo_full_name"], r["ecosystem"], r["package_name"], r["osv_id"])
            for r in records
        }
        resolved_count, resolved_repos = _resolve_stale_findings(db, current_keys)

        # Issue クローズ失敗はクロール全体を失敗させない（Issue起票と同じ方針）
        try:
            _close_resolved_repo_issues(db, resolved_repos)
        except Exception as exc:
            logger.error("Failed to close resolved GitHub issues: %s", exc, exc_info=True)

        # 保持期間超過の削除失敗はクロール全体を失敗させない（KEV/OSV/JVN と同様の方針）
        try:
            purged_count = _delete_old_depscan_records(db)
        except Exception as exc:
            logger.error("Failed to delete old DEPSCAN records: %s", exc, exc_info=True)

    except Exception as exc:
        write_crawler_log(
            crawler_type="DEPSCAN",
            status="error",
            started_at=started_at,
            finished_at=now_utc(),
            inserted=new_count,
            updated=purged_count,
            deleted=resolved_count,
            error_message=str(exc),
        )
        notify_error("DEPSCAN", str(exc))
        raise
    finally:
        db.close()

    logger.info(
        "=== DEPSCAN completed: new=%d, resolved=%d, purged=%d, repos=%d ===",
        new_count, resolved_count, purged_count, repos_scanned,
    )
    write_crawler_log(
        crawler_type="DEPSCAN",
        status="success",
        started_at=started_at,
        finished_at=now_utc(),
        inserted=new_count,
        updated=purged_count,
        deleted=resolved_count,
    )
    notify_dependency_findings(new_snapshots)
    _file_github_issues(new_snapshots)
    return new_count, resolved_count, repos_scanned
