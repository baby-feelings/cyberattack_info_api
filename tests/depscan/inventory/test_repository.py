"""app.depscan.inventory（依存の全量の永続化）のテスト。"""
import os
from unittest.mock import patch

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.depscan.inventory import RepoDependencyRepository  # noqa: E402
from app.depscan.models import RepoDependency  # noqa: E402


def _rows(db_session) -> set[tuple[str, str, str, str, str]]:
    return {
        (r.repo_full_name, r.ecosystem, r.package_name, r.version, r.manifest_path)
        for r in db_session.query(RepoDependency).all()
    }


def _add(db_session, repo: str, name: str, version: str = "1.0.0") -> None:
    db_session.add(RepoDependency(
        repo_full_name=repo, ecosystem="PyPI", package_name=name, version=version,
        manifest_path="requirements.txt",
    ))
    db_session.commit()


class TestReplace:
    def test_saves_all_dependencies_with_their_manifest(self, db_session):
        dep_to_repos = {
            ("PyPI", "fastapi", "0.1"): [("u/a", "requirements.txt")],
            ("npm", "axios", "1.6.0"): [
                ("u/a", "web/package-lock.json"), ("u/b", "package-lock.json"),
            ],
        }

        saved = RepoDependencyRepository(db_session).replace(dep_to_repos, ["u/a", "u/b"])

        assert saved == 3
        assert _rows(db_session) == {
            ("u/a", "PyPI", "fastapi", "0.1", "requirements.txt"),
            ("u/a", "npm", "axios", "1.6.0", "web/package-lock.json"),
            ("u/b", "npm", "axios", "1.6.0", "package-lock.json"),
        }

    def test_replaces_previous_rows_of_scanned_repos(self, db_session):
        """依存を外した・版を上げたリポジトリの古い行が残らないこと。"""
        _add(db_session, "u/a", "old-pkg")
        _add(db_session, "u/a", "pkg", "1.0.0")

        RepoDependencyRepository(db_session).replace(
            {("PyPI", "pkg", "2.0.0"): [("u/a", "requirements.txt")]}, ["u/a"],
        )

        assert _rows(db_session) == {("u/a", "PyPI", "pkg", "2.0.0", "requirements.txt")}

    def test_scanned_repo_without_dependencies_is_cleared(self, db_session):
        """ロックファイルを削除したリポジトリ（依存が0件）の行も消えること。"""
        _add(db_session, "u/a", "pkg")

        RepoDependencyRepository(db_session).replace({}, ["u/a"])

        assert _rows(db_session) == set()

    def test_does_not_touch_repos_that_were_not_scanned(self, db_session):
        """スキャン対象外（他のオーナー等）のリポジトリの行は変更しないこと。"""
        _add(db_session, "other/repo", "pkg")

        RepoDependencyRepository(db_session).replace(
            {("PyPI", "fastapi", "0.1"): [("u/a", "requirements.txt")]}, ["u/a"],
        )

        assert ("other/repo", "PyPI", "pkg", "1.0.0", "requirements.txt") in _rows(db_session)

    def test_deduplicates_repeated_entries(self, db_session):
        """同じロックファイルに同じ (パッケージ, 版) が複数回載っても1行にまとまること。"""
        dep_to_repos = {
            ("PyPI", "pkg", "1.0"): [("u/a", "requirements.txt"), ("u/a", "requirements.txt")],
        }

        saved = RepoDependencyRepository(db_session).replace(dep_to_repos, ["u/a"])

        assert saved == 1
        assert db_session.query(RepoDependency).count() == 1

    def test_saves_more_rows_than_one_batch(self, db_session):
        dep_to_repos = {
            ("npm", f"pkg-{i}", "1.0.0"): [("u/a", "package-lock.json")] for i in range(2500)
        }

        saved = RepoDependencyRepository(db_session).replace(dep_to_repos, ["u/a"])

        assert saved == 2500
        assert db_session.query(RepoDependency).count() == 2500

    def test_rolls_back_and_keeps_old_rows_on_failure(self, db_session):
        """挿入に失敗したら削除も取り消され、古い行がそのまま残ること。"""
        _add(db_session, "u/a", "keep-me")

        with patch.object(
            db_session, "bulk_insert_mappings", side_effect=RuntimeError("db down"),
        ), pytest.raises(RuntimeError):
            RepoDependencyRepository(db_session).replace(
                {("PyPI", "new", "1.0"): [("u/a", "requirements.txt")]}, ["u/a"],
            )

        assert _rows(db_session) == {("u/a", "PyPI", "keep-me", "1.0.0", "requirements.txt")}
