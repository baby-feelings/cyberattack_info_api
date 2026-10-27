"""app.core.owner_scope（リポジトリの所有者による絞り込み・所有の判定）のテスト。"""
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.core.owner_scope import is_owned_by, owner_prefix, restrict_to_owner  # noqa: E402
from app.runtimes.models import RepoRuntime  # noqa: E402


class TestIsOwnedBy:
    def test_matches_the_owner_prefix_only(self):
        assert is_owned_by("alice/web", "alice")
        assert not is_owned_by("alice-corp/web", "alice")  # 接頭辞が似ているだけの別のオーナー
        assert not is_owned_by("bob/web", "alice")
        assert not is_owned_by("alice", "alice")  # `owner/` を含まない

    def test_prefix_includes_the_slash(self):
        assert owner_prefix("alice") == "alice/"


class TestRestrictToOwner:
    def _seed(self, db_session):
        for repo in ("a_b/app", "aXb/app", "alice/web", "bob/web"):
            db_session.add(RepoRuntime(
                repo_full_name=repo, runtime="python", cycle="3.13", source_path="x", pinned=True,
            ))
        db_session.commit()

    def _repos(self, db_session, owner):
        query = restrict_to_owner(db_session.query(RepoRuntime), RepoRuntime.repo_full_name, owner)
        return sorted(r.repo_full_name for r in query.all())

    def test_none_does_not_restrict(self, db_session):
        self._seed(db_session)
        assert len(self._repos(db_session, None)) == 4

    def test_restricts_to_the_owner(self, db_session):
        self._seed(db_session)
        assert self._repos(db_session, "alice") == ["alice/web"]

    def test_underscore_is_not_a_wildcard(self, db_session):
        """`_` は LIKE のワイルドカードのため、前方一致で絞る（`a_b` が `aXb` に一致しない）。"""
        self._seed(db_session)
        assert self._repos(db_session, "a_b") == ["a_b/app"]
