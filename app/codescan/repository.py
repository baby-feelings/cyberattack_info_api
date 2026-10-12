"""`CodeFinding`（CODESCAN の検知結果）の永続化（Upsert・解決済み化・保持期間超過の削除）。

DB 操作をクローラー（走査の組み立て）から分離する。DEPSOPS の `PrLogRepository` と同じく
`Session` を持つクラスにして、呼び出し側は「このリポジトリの検知結果を反映する」と頼むだけにする。
"""
import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.codescan.models import CodeFinding
from app.core.config import settings
from app.crawler_logs.writer import now_utc

logger = logging.getLogger(__name__)

# (repo_full_name, file_path, rule_id, line_start) キー型のエイリアス（Upsertの基準キー）
FindingKey = tuple[str, str, str, int]


@dataclass
class SyncResult:
    """1リポジトリ分の検知結果を反映した結果。"""

    inserted: int = 0
    # 新規挿入されたレコードのスナップショット（GitHub Issue 起票用。DB セッションクローズ後の
    # DetachedInstanceError を避けるため ORM オブジェクトではなく辞書で持つ）
    new_snapshots: list[dict[str, Any]] = field(default_factory=list)
    # 今回の検査で検知されなくなり、解決済みにした件数
    resolved: int = 0


def key_of(record: dict[str, Any]) -> FindingKey:
    """レコードの Upsert の基準キー。"""
    return (record["repo_full_name"], record["file_path"], record["rule_id"], record["line_start"])


class CodeFindingRepository:
    """`CodeFinding` の永続化。"""

    def __init__(self, db: Session) -> None:
        self._db = db

    def sync(self, full_name: str, records: list[dict[str, Any]]) -> SyncResult:
        """1リポジトリの今回の検査結果を反映する（Upsert + 検知されなくなったものを解決済みに）。

        CODESCAN はリポジトリ単位で全ファイルを検査し直すため、DEPSCAN のような全体横断の差分判定
        ではなく、リポジトリ単位で「今回の結果に含まれない前回の未解決 finding」を解決済みにする。
        """
        inserted, snapshots = self.upsert(full_name, records)
        resolved = self.resolve_stale(full_name, {key_of(r) for r in records})
        return SyncResult(inserted=inserted, new_snapshots=snapshots, resolved=resolved)

    def upsert(
        self, full_name: str, records: list[dict[str, Any]],
    ) -> tuple[int, list[dict[str, Any]]]:
        """1リポジトリ分の `CodeFinding` を Upsert する。

        Returns:
            (新規挿入件数, 新規挿入されたレコードのスナップショット辞書リスト)
        """
        db = self._db
        inserted = 0
        new_snapshots: list[dict[str, Any]] = []
        seen_keys: set[FindingKey] = set()

        for rec in records:
            key = key_of(rec)
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
                for name, value in rec.items():
                    setattr(existing, name, value)
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
                # "tool"キーは既存テストの一部で省略されうるため .get で後方互換を保つ
                # （省略時は既存値を変更しない方が安全だが、Semgrep/gitleaksの実装では
                # 常に付与されるため実運用上は必ず更新される）
                existing.tool = rec.get("tool", existing.tool)

        db.commit()
        return inserted, new_snapshots

    def resolve_stale(self, full_name: str, current_keys: set[FindingKey]) -> int:
        """1リポジトリについて、今回の検査で検知されなくなった未解決 finding を解決済みにする。"""
        db = self._db
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

    def delete_old_resolved(self) -> int:
        """保持期間（CODESCAN_RETENTION_DAYS）を超えて解決済みのままのレコードを削除する。

        DEPSCAN と同じ方針で、未解決のレコードは対象外。
        """
        cutoff = now_utc() - timedelta(days=settings.CODESCAN_RETENTION_DAYS)
        deleted = (
            self._db.query(CodeFinding)
            .filter(
                CodeFinding.resolved_at.is_not(None),
                CodeFinding.resolved_at < cutoff,
            )
            .delete(synchronize_session=False)
        )
        self._db.commit()
        logger.info("CODESCAN old resolved records deleted: %d (resolved_at < %s)", deleted, cutoff)
        return deleted
