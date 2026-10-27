"""言語・実行環境のバージョン監視（RUNTIME）の永続化。"""
import logging
from collections.abc import Iterable

from sqlalchemy.orm import Session

from app.runtimes.detector import DetectedRuntime
from app.runtimes.eol_client import ReleaseInfo
from app.runtimes.models import RepoRuntime, RuntimeRelease

logger = logging.getLogger(__name__)


class RuntimeReleaseRepository:
    """`runtime_releases` テーブルの永続化。"""

    def __init__(self, db: Session) -> None:
        self.db = db

    def upsert(self, infos: Iterable[ReleaseInfo]) -> int:
        """取得したリリース情報を、(言語, 系列) をキーに登録・更新する。

        取得元に無くなった系列は消さない（EOL を過ぎて一覧から外れた古い系列を使っている
        リポジトリの判定に、過去の情報が必要なため）。

        Returns:
            登録・更新した件数
        """
        existing = {(r.runtime, r.cycle): r for r in self.db.query(RuntimeRelease).all()}
        count = 0
        try:
            for info in infos:
                row = existing.get((info.runtime, info.cycle))
                if row is None:
                    row = RuntimeRelease(runtime=info.runtime, cycle=info.cycle)
                    self.db.add(row)
                row.latest_version = info.latest_version
                row.release_date = info.release_date
                row.eol_date = info.eol_date
                row.is_eol = info.is_eol
                row.is_lts = info.is_lts
                count += 1
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        return count


class RepoRuntimeRepository:
    """`repo_runtimes` テーブルの永続化。"""

    def __init__(self, db: Session) -> None:
        self.db = db

    def replace(self, repo_full_name: str, detected: Iterable[DetectedRuntime]) -> int:
        """リポジトリが使っている言語・実行環境を、今回の検出結果で置き換える。

        設定ファイルが現在の正のため、そのリポジトリの既存行は一度すべて消して入れ直す
        （削除した設定・使わなくなった言語が残らないようにするため）。削除と挿入は
        同じトランザクションで行い、失敗したときは古い内容が残る。

        Returns:
            保存した行数
        """
        rows = {(d.runtime, d.cycle, d.source_path): d for d in detected}
        try:
            self.db.query(RepoRuntime).filter(
                RepoRuntime.repo_full_name == repo_full_name,
            ).delete(synchronize_session=False)
            for runtime, cycle, source_path in sorted(rows):
                self.db.add(RepoRuntime(
                    repo_full_name=repo_full_name,
                    runtime=runtime,
                    cycle=cycle,
                    source_path=source_path,
                    pinned=rows[(runtime, cycle, source_path)].pinned,
                ))
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        return len(rows)
