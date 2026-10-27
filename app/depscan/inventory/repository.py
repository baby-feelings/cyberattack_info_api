"""依存パッケージの全量（インベントリ）の永続化（DEPSCAN。SBOM・横断検索用）。

`DependencyFindingRepository` が「脆弱な依存」だけを保存するのに対し、こちらは「使っている
依存の全量」を保存する。収集（`manifests.collect_dependencies`）が返す結果をそのまま使い、
OSV との照合には依存しない（脆弱性が無い依存も SBOM には必要なため）。
"""
import logging
from collections.abc import Iterable

from sqlalchemy.orm import Session

from app.depscan.manifests import DepKey
from app.depscan.models import RepoDependency

logger = logging.getLogger(__name__)

# 1回の INSERT に渡す行数（ロックファイルが大きいリポジトリでも1文が肥大化しないようにする）
_BATCH_SIZE = 1000


class RepoDependencyRepository:
    """`repo_dependencies` テーブルの永続化。"""

    def __init__(self, db: Session) -> None:
        self.db = db

    def replace(
        self,
        dep_to_repos: dict[DepKey, list[tuple[str, str]]],
        scanned_repos: Iterable[str],
    ) -> int:
        """スキャンしたリポジトリの依存の全量を、今回の結果で置き換える。

        ロックファイルが現在の正のため、スキャン対象のリポジトリの既存行は一度すべて消し、
        今回見つかった依存を入れ直す（依存を外したリポジトリ・ロックファイルを削除した
        リポジトリの古い行が残らないようにするため）。スキャン対象外のリポジトリ
        （他のオーナーなど）には触れない。削除と挿入は同じトランザクションで行う。

        Args:
            dep_to_repos: `{(ecosystem, package_name, version): [(repo, manifest_path)]}`
            scanned_repos: 今回スキャンしたリポジトリの full_name（依存が無かったものも含む）

        Returns:
            保存した依存の行数
        """
        scanned = set(scanned_repos)
        # ロックファイルに同じ (パッケージ, 版) が複数回載ることがあるため、重複を除く（一意制約）
        rows = {
            (repo, ecosystem, name, version, path)
            for (ecosystem, name, version), locations in dep_to_repos.items()
            for repo, path in locations
        }
        try:
            if scanned:
                self.db.query(RepoDependency).filter(
                    RepoDependency.repo_full_name.in_(scanned),
                ).delete(synchronize_session=False)
            ordered = sorted(rows)
            for start in range(0, len(ordered), _BATCH_SIZE):
                self.db.bulk_insert_mappings(
                    RepoDependency,  # type: ignore[arg-type]
                    [
                        {
                            "repo_full_name": repo,
                            "ecosystem": ecosystem,
                            "package_name": name,
                            "version": version,
                            "manifest_path": path,
                        }
                        for repo, ecosystem, name, version, path
                        in ordered[start:start + _BATCH_SIZE]
                    ],
                )
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        logger.info(
            "DEPSCAN inventory: %d dependencies saved for %d repos", len(rows), len(scanned),
        )
        return len(rows)
