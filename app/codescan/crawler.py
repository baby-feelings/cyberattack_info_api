"""自アプリのコード脆弱性スキャナー（CODESCAN）モジュール。

GitHub 上の自作アプリ全リポジトリのソースコードを tarball で取得し、Semgrep
（`p/security-audit` + `p/secrets` ルールセット）で静的解析する。DEPSCAN
（依存ライブラリの既知脆弱性）とは異なる検知種別として、自アプリのコード自体に
潜む脆弱性パターン（SQLi・ハードコード認証情報・XSS等）を検知する。

対象リポジトリ一覧は DEPSCAN と完全に同じ（`GITHUB_USERNAME` 配下、fork・
archived 除外）ため `app.depscan.github_client.list_target_repos` を再利用する
（DRY原則）。オーケストレーションは KEV/OSV/JVN と同じ `app.core.crawler_runner
.run_crawler`（Template Method）+ `CrawlCounters` を使う。DEPSCAN が独自の
オーケストレーションを持つ（詳細なSlackダイジェスト・Issueクローズ判定等が
複雑なため）のとは異なり、CODESCANは通知を`notify_success`/`notify_error`の
汎用フォーマットのみで済ませる設計とした（要件どおり）。

APScheduler から毎日呼び出される。
"""
import io
import json
import logging
import os
import subprocess
import tarfile
import tempfile
from datetime import timedelta
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.codescan.cvss_mapping import estimate_cvss_vector
from app.codescan.github_client import download_repo_tarball
from app.codescan.issue_management import _file_github_issues
from app.codescan.models import CodeFinding
from app.core.config import settings
from app.core.crawler_runner import CrawlCounters, run_crawler
from app.core.cvss import calculate_base_score
from app.crawler_logs.writer import now_utc
from app.depscan.github_client import list_target_repos

logger = logging.getLogger(__name__)

# (repo_full_name, file_path, rule_id, line_start) キー型のエイリアス（Upsertの基準キー）
FindingKey = tuple[str, str, str, int]

# 1リポジトリあたりのSemgrepサブプロセス全体のタイムアウト（秒）。OCI本番は
# 1 OCPU/6GBの限られたリソースのため、1リポジトリのスキャンが長時間ブロックすると
# 他のクローラー・CODESCAN全体を圧迫するリスクがある。超過時はそのリポジトリのみ
# スキップしログに記録し、CODESCAN全体は継続する
_SEMGREP_SUBPROCESS_TIMEOUT_SECONDS = 300
# Semgrep自体の内部タイムアウト（1ルール×1ファイルあたり、秒）
_SEMGREP_RULE_TIMEOUT_SECONDS = "120"
# コードスニペットの保存上限文字数（生成物混入等の異常ケースでDBが肥大化しないため）
_MAX_SNIPPET_LEN = 2000


def _extract_tarball(tarball_bytes: bytes, dest_dir: str) -> str:
    """tarball を安全に展開し、リポジトリソースのルートディレクトリパスを返す。

    GitHub の tarball エンドポイントは常に単一のトップレベルディレクトリ
    （例: `owner-repo-<sha>/`）を含むため、それを見つけてルートとして返す。
    パストラバーサル対策として `filter="data"`（PEP 706）で安全に展開する。
    """
    with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz") as tar:
        try:
            tar.extractall(dest_dir, filter="data")
        except TypeError:
            # Python 3.11.4未満等、filter引数非対応の古いtarfileへのフォールバック
            # （本プロジェクトは3.11系を使うが、念のため後方互換を確保する）
            tar.extractall(dest_dir)  # noqa: S202

    entries = [
        e for e in os.listdir(dest_dir) if os.path.isdir(os.path.join(dest_dir, e))
    ]
    return os.path.join(dest_dir, entries[0]) if entries else dest_dir


def _run_semgrep(target_dir: str) -> dict[str, Any]:
    """Semgrep を実行し JSON 出力をパースして返す薄いラッパー。

    実際のバイナリ呼び出しをこの関数に閉じ込めることで、Semgrep 非依存の
    テスト（このラッパー自体をモックする）を可能にする。1リポジトリあたりの
    タイムアウトを必ず設定する（超過時は `subprocess.TimeoutExpired` を送出し、
    呼び出し元 `_scan_repo` の try/except でそのリポジトリのみスキップされる）。
    """
    result = subprocess.run(  # noqa: S603
        [
            "semgrep",
            "--config=p/security-audit",
            "--config=p/secrets",
            "--json",
            "--timeout", _SEMGREP_RULE_TIMEOUT_SECONDS,
            "--quiet",
            target_dir,
        ],
        capture_output=True,
        timeout=_SEMGREP_SUBPROCESS_TIMEOUT_SECONDS,
        text=True,
        check=False,
    )
    return dict(json.loads(result.stdout or "{}"))


def _parse_semgrep_results(
    full_name: str, semgrep_json: dict[str, Any], repo_root: str,
) -> list[dict[str, Any]]:
    """Semgrep の JSON 出力を `CodeFinding` 相当のレコード辞書リストへ変換する。

    CVSS 3.1 スコア・ベクターはこの時点で `app.codescan.cvss_mapping`
    （ベストエフォート推定）+ `app.core.cvss`（正式な計算式）により算出する。
    """
    now = now_utc()
    records: list[dict[str, Any]] = []

    for item in semgrep_json.get("results", []):
        raw_path = item.get("path", "")
        try:
            rel_path = os.path.relpath(raw_path, repo_root)
        except ValueError:
            # Windows でドライブレターが異なる等、relpath 不能な場合のフォールバック
            rel_path = raw_path
        rel_path = rel_path.replace("\\", "/")

        extra = item.get("extra", {})
        metadata = extra.get("metadata", {}) or {}

        cwe_raw = metadata.get("cwe") or []
        cwe_list = list(cwe_raw) if isinstance(cwe_raw, list) else [str(cwe_raw)]
        owasp_raw = metadata.get("owasp") or []
        owasp_list = list(owasp_raw) if isinstance(owasp_raw, list) else [str(owasp_raw)]

        severity = str(extra.get("severity") or "INFO").upper()
        snippet = str(extra.get("lines") or "")[:_MAX_SNIPPET_LEN]

        cvss_score: float | None = None
        cvss_vector: str | None = None
        try:
            cvss_vector = estimate_cvss_vector(severity, cwe_list)
            cvss_score = calculate_base_score(cvss_vector)
        except ValueError as exc:
            logger.warning(
                "CODESCAN: failed to estimate CVSS for %s: %s", item.get("check_id"), exc,
            )

        records.append({
            "repo_full_name": full_name,
            "file_path": rel_path,
            "line_start": int(item.get("start", {}).get("line", 0)),
            "line_end": int(item.get("end", {}).get("line", 0)),
            "rule_id": str(item.get("check_id", "")),
            "message": str(extra.get("message") or "").strip(),
            "severity": severity,
            "cwe_ids": cwe_list,
            "owasp_categories": owasp_list,
            "code_snippet": snippet,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "detected_at": now,
        })

    return records


def _scan_repo(full_name: str, branch: str, token: str) -> list[dict[str, Any]]:
    """1リポジトリを tarball 取得 → 展開 → Semgrep 実行 → パースする。

    tempfile.TemporaryDirectory() でスキャン用の一時ディレクトリを作成し、
    スキャン完了後（例外発生時含む）に確実に削除する。
    """
    owner, repo = full_name.split("/", 1)
    tarball_bytes = download_repo_tarball(owner, repo, token, branch)

    with tempfile.TemporaryDirectory() as tmpdir:
        repo_root = _extract_tarball(tarball_bytes, tmpdir)
        semgrep_json = _run_semgrep(repo_root)
        return _parse_semgrep_results(full_name, semgrep_json, repo_root)


def _upsert_repo_findings(
    db: Session, full_name: str, records: list[dict[str, Any]],
) -> tuple[int, list[dict[str, Any]]]:
    """1リポジトリ分の `CodeFinding` を Upsert する。

    Returns:
        (新規挿入件数, 新規挿入されたレコードのスナップショット辞書リスト)
        スナップショットは GitHub Issue 起票用（DB セッションクローズ後の
        DetachedInstanceError を避けるため ORM オブジェクトではなく辞書で返す）
    """
    inserted = 0
    new_snapshots: list[dict[str, Any]] = []
    seen_keys: set[FindingKey] = set()

    for rec in records:
        key: FindingKey = (
            rec["repo_full_name"], rec["file_path"], rec["rule_id"], rec["line_start"],
        )
        if key in seen_keys:
            continue
        seen_keys.add(key)

        existing = (
            db.query(CodeFinding)
            .filter(
                CodeFinding.repo_full_name == rec["repo_full_name"],
                CodeFinding.file_path == rec["file_path"],
                CodeFinding.rule_id == rec["rule_id"],
                CodeFinding.line_start == rec["line_start"],
            )
            .first()
        )

        if existing is None:
            db.add(CodeFinding(**rec))
            inserted += 1
            new_snapshots.append(rec)
        elif existing.resolved_at is not None:
            # 一度解決した後に再発したケース: 解決フラグを解除し内容を最新化する
            for field, value in rec.items():
                setattr(existing, field, value)
            existing.resolved_at = None
        else:
            # 既存の未解決レコード: Semgrepのルール更新等でmessage/severity/CVSSが
            # 変わりうるため、毎回のスキャンで内容を最新化する
            existing.message = rec["message"]
            existing.severity = rec["severity"]
            existing.line_end = rec["line_end"]
            existing.cwe_ids = rec["cwe_ids"]
            existing.owasp_categories = rec["owasp_categories"]
            existing.code_snippet = rec["code_snippet"]
            existing.cvss_score = rec["cvss_score"]
            existing.cvss_vector = rec["cvss_vector"]

    db.commit()
    return inserted, new_snapshots


def _resolve_stale_repo_findings(
    db: Session, full_name: str, current_keys: set[FindingKey],
) -> int:
    """1リポジトリについて、今回のスキャンで検知されなくなった未解決 finding を
    解決済みにする。

    CODESCAN はリポジトリ単位で全ファイルをスキャンし直すため、DEPSCAN のような
    全体横断の差分判定ではなく、リポジトリ単位で「今回のスキャン結果に含まれない
    前回の未解決 finding」を解決済みにする設計にした。
    """
    resolved = 0
    now = now_utc()
    open_findings = (
        db.query(CodeFinding)
        .filter(CodeFinding.repo_full_name == full_name, CodeFinding.resolved_at.is_(None))
        .all()
    )
    for finding in open_findings:
        key: FindingKey = (
            finding.repo_full_name, finding.file_path, finding.rule_id, finding.line_start,
        )
        if key not in current_keys:
            finding.resolved_at = now
            resolved += 1
    db.commit()
    return resolved


def _delete_old_codescan_records(db: Session) -> int:
    """保持期間（CODESCAN_RETENTION_DAYS）を超えて解決済みのままの CODESCAN
    レコードを削除する（DEPSCAN と同じ方針: 未解決のレコードは対象外）。
    """
    cutoff = now_utc() - timedelta(days=settings.CODESCAN_RETENTION_DAYS)
    deleted = (
        db.query(CodeFinding)
        .filter(
            CodeFinding.resolved_at.is_not(None),
            CodeFinding.resolved_at < cutoff,
        )
        .delete(synchronize_session=False)
    )
    db.commit()
    logger.info("CODESCAN old resolved records deleted: %d (resolved_at < %s)", deleted, cutoff)
    return deleted


def _run_codescan_body(db: Session, counters: CrawlCounters) -> None:
    """CODESCAN 本体処理（`run_crawler` へ渡す body 関数）。

    リポジトリ単位で try/except し、1リポジトリの失敗（tarball取得失敗・
    Semgrepタイムアウト・JSON解析失敗等）が CODESCAN 全体を止めないようにする
    （DEPSCAN のGitHub API呼び出し失敗時と同じper-repoパターン）。

    `CrawlCounters` へのマッピングは DEPSCAN の crawler_logs 記録方針を踏襲する:
    inserted=新規検知件数、deleted=今回解決済みにした件数、updated=保持期間超過の
    実削除件数。
    """
    username = settings.GITHUB_USERNAME
    token = settings.GITHUB_TOKEN
    repos = list_target_repos(username, token)
    logger.info("CODESCAN: %d target repos to scan", len(repos))

    all_new_snapshots: list[dict[str, Any]] = []

    for i, repo_info in enumerate(repos, start=1):
        full_name = repo_info["full_name"]
        default_branch = repo_info.get("default_branch") or "main"
        logger.info("CODESCAN: [%d/%d] scanning %s", i, len(repos), full_name)

        try:
            records = _scan_repo(full_name, default_branch, token)
        except (httpx.HTTPError, subprocess.TimeoutExpired, tarfile.TarError,
                json.JSONDecodeError, OSError) as exc:
            logger.warning("CODESCAN: failed to scan %s, skipping: %s", full_name, exc)
            continue

        inserted, new_snapshots = _upsert_repo_findings(db, full_name, records)
        counters.inserted += inserted
        all_new_snapshots.extend(new_snapshots)

        current_keys: set[FindingKey] = {
            (r["repo_full_name"], r["file_path"], r["rule_id"], r["line_start"])
            for r in records
        }
        counters.deleted += _resolve_stale_repo_findings(db, full_name, current_keys)

    # 保持期間超過の削除失敗はクロール全体を失敗させない（DEPSCAN/KEV/OSV/JVNと同様の方針）
    try:
        counters.updated = _delete_old_codescan_records(db)
    except Exception as exc:
        logger.error("CODESCAN: failed to delete old records: %s", exc, exc_info=True)

    # Issue起票失敗はクロール全体を失敗させない（DEPSCANと同じ方針）
    try:
        _file_github_issues(all_new_snapshots)
    except Exception as exc:
        logger.error("CODESCAN: failed to file GitHub issues: %s", exc, exc_info=True)


def fetch_and_scan_code() -> tuple[int, int, int]:
    """CODESCAN のメインエントリポイント。

    GitHub 上の全対象リポジトリのソースコードを Semgrep で静的解析し、自アプリの
    コード自体に潜む脆弱性を検知する。結果は crawler_logs に記録し、新規検知が
    あれば Slack に通知する（`app.core.crawler_runner.run_crawler` 経由）。
    APScheduler から毎日呼び出される。

    Returns:
        (inserted, updated, deleted) のタプル
        （inserted=新規検知件数, updated=保持期間超過の削除件数,
        deleted=今回解決済みにした件数）
    """
    logger.info("=== CODESCAN started ===")
    result = run_crawler("CODESCAN", _run_codescan_body)
    logger.info(
        "=== CODESCAN completed: inserted=%d, updated=%d, deleted=%d ===", *result,
    )
    return result
