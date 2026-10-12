"""`DependencyFinding`（DEPSCAN の検知結果）の永続化（Upsert・解決済み化・保持期間超過の削除）。

DB 操作をクローラー（ジョブの組み立て）から分離する。DEPSOPS の `PrLogRepository`、CODESCAN の
`CodeFindingRepository` と同じく `Session` を持つクラスにして、呼び出し側は「今回の検知結果を
反映する」と頼むだけにする。
"""
import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.crawler_logs.writer import now_utc
from app.depscan.models import DependencyFinding

logger = logging.getLogger(__name__)

# (repo_full_name, ecosystem, package_name, osv_id) キー型のエイリアス
FindingKey = tuple[str, str, str, str]


@dataclass
class SyncResult:
    """今回の検知結果を反映した結果。"""

    inserted: int = 0
    # 新規挿入されたレコードのスナップショット（Slack 通知・Issue 起票用。DB セッションクローズ後の
    # DetachedInstanceError を避けるため ORM オブジェクトではなく辞書で持つ）
    new_snapshots: list[dict[str, Any]] = field(default_factory=list)
    # 今回の検査で検知されなくなり、解決済みにした件数
    resolved: int = 0
    # 今回1件以上解決したリポジトリ（Issue クローズ判定が必要なリポジトリの絞り込み用）
    resolved_repos: set[str] = field(default_factory=set)


def key_of(record: dict[str, Any]) -> FindingKey:
    """レコードの Upsert の基準キー。"""
    return (record["repo_full_name"], record["ecosystem"], record["package_name"], record["osv_id"])


class DependencyFindingRepository:
    """`DependencyFinding` の永続化。"""

    def __init__(self, db: Session) -> None:
        self._db = db

    def sync(
        self, records: list[dict[str, Any]], repo_owner_prefix: str | None = None,
    ) -> SyncResult:
        """今回の検知結果を反映する（Upsert + 検知されなくなったものを解決済みに）。

        Args:
            repo_owner_prefix: 指定した場合、解決済み化の対象をそのオーナーのリポジトリに限る
                （オンデマンドの個人スキャンが、無関係な他リポジトリの未解決レコードまで
                誤って解決済みにしないため）。
        """
        inserted, snapshots = self.upsert(records)
        resolved, resolved_repos = self.resolve_stale(
            {key_of(r) for r in records}, repo_owner_prefix=repo_owner_prefix,
        )
        return SyncResult(inserted, snapshots, resolved, resolved_repos)

    def upsert(
        self, records: list[dict[str, Any]],
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
                self._db.query(DependencyFinding)
                .filter(
                    DependencyFinding.repo_full_name == rec["repo_full_name"],
                    DependencyFinding.ecosystem == rec["ecosystem"],
                    DependencyFinding.package_name == rec["package_name"],
                    DependencyFinding.osv_id == rec["osv_id"],
                )
                .first()
            )

            if existing is None:
                self._db.add(DependencyFinding(**rec))
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
                # 修正版は、新たに判明した（レジストリからの補完を含む）場合のみ反映する。
                # 一時的にレジストリを引けなかった回に空で上書きしてしまわないようにするため
                if rec.get("fixed_versions"):
                    existing.fixed_versions = rec["fixed_versions"]

        self._db.commit()
        return inserted, new_snapshots

    def resolve_stale(
        self, current_keys: set[FindingKey], repo_owner_prefix: str | None = None,
    ) -> tuple[int, set[str]]:
        """今回のスキャンで検知されなくなった未解決 Finding を解決済みにする。

        Args:
            repo_owner_prefix: 指定した場合、`"{prefix}/"` から始まるリポジトリのみを
                対象にする（オンデマンドの個人スキャンが、無関係な他リポジトリの
                未解決レコードまで誤って解決済みにしてしまわないようにするため）。

        Returns:
            (解決件数, 今回1件以上解決した repo_full_name の集合)。
            後者は close_resolved_repo_issues が「Issue クローズ判定が必要な
            リポジトリ」を絞り込むために使う（何も解決していないリポジトリを
            毎回チェックする無駄を避けるため）。
        """
        resolved = 0
        affected_repos: set[str] = set()
        now = now_utc()
        query = self._db.query(DependencyFinding).filter(DependencyFinding.resolved_at.is_(None))
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
        self._db.commit()
        return resolved, affected_repos

    def delete_old_resolved(self) -> int:
        """保持期間（DEPSCAN_RETENTION_DAYS）を超えて解決済みのままの DEPSCAN レコードを削除する。

        resolved_at が cutoff より古い（=解決済みのまま長期間経過した）レコードのみを
        対象とする。未解決のレコードは対応が必要な情報のため、経過期間に関わらず削除しない。

        Returns:
            削除件数
        """
        cutoff = now_utc() - timedelta(days=settings.DEPSCAN_RETENTION_DAYS)
        deleted = (
            self._db.query(DependencyFinding)
            .filter(
                DependencyFinding.resolved_at.is_not(None),
                DependencyFinding.resolved_at < cutoff,
            )
            .delete(synchronize_session=False)
        )
        self._db.commit()
        logger.info("DEPSCAN old resolved records deleted: %d (resolved_at < %s)", deleted, cutoff)
        return deleted
