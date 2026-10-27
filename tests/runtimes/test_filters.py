"""app.runtimes.filters（言語・実行環境の絞り込み条件）と、browse の集計のテスト。"""
import os
from datetime import date
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.runtimes.browse import list_runtimes, summarize_repos  # noqa: E402
from app.runtimes.filters import RuntimeFilter  # noqa: E402
from app.runtimes.models import RepoRuntime, RuntimeRelease  # noqa: E402

_TODAY = date(2026, 10, 27)


def _seed(db):
    db.add_all([
        RuntimeRelease(runtime="python", cycle="3.14", latest_version="3.14.10",
                       eol_date=date(2030, 10, 31), is_eol=False, is_lts=False,
                       release_date=date(2025, 10, 7)),
        RuntimeRelease(runtime="python", cycle="3.10", latest_version="3.10.20",
                       eol_date=date(2026, 10, 1), is_eol=True, is_lts=False),
        RuntimeRelease(runtime="nodejs", cycle="24", latest_version="24.22.1",
                       eol_date=date(2028, 4, 30), is_eol=False, is_lts=True,
                       release_date=date(2025, 5, 6)),
    ])
    for repo, runtime, cycle in [
        ("alice/web", "python", "3.10"),   # eol（対応が必要）
        ("alice/web", "nodejs", "24"),     # latest
        ("alice/api", "python", "3.14"),   # latest
        ("bob/app", "python", "3.10"),     # eol
    ]:
        db.add(RepoRuntime(repo_full_name=repo, runtime=runtime, cycle=cycle,
                           source_path="x", pinned=True))
    db.commit()


def _repos(rows):
    return sorted({(r.repo_full_name, r.runtime) for r, _ in rows})


class TestRuntimeFilter:
    def test_default_returns_everything(self, db_session):
        _seed(db_session)
        assert len(list_runtimes(db_session, RuntimeFilter(), today=_TODAY)) == 4

    def test_each_condition_narrows(self, db_session):
        _seed(db_session)
        by_repo = list_runtimes(db_session, RuntimeFilter(repo="alice/web"), today=_TODAY)
        by_runtime = list_runtimes(db_session, RuntimeFilter(runtime="nodejs"), today=_TODAY)
        assert _repos(by_repo) == [("alice/web", "nodejs"), ("alice/web", "python")]
        assert _repos(by_runtime) == [("alice/web", "nodejs")]

    def test_needs_action_is_applied_after_the_state_is_known(self, db_session):
        _seed(db_session)
        rows = list_runtimes(db_session, RuntimeFilter(needs_action=True), today=_TODAY)
        assert {st.state for _, st in rows} == {"eol"}
        assert _repos(rows) == [("alice/web", "python"), ("bob/app", "python")]

    def test_for_owner_returns_a_new_restricted_filter(self, db_session):
        _seed(db_session)
        base = RuntimeFilter()
        restricted = base.for_owner("alice")
        assert base.owner is None and restricted.owner == "alice"
        assert {r.repo_full_name for r, _ in list_runtimes(
            db_session, restricted, today=_TODAY)} == {"alice/web", "alice/api"}

    def test_operating_filter(self, db_session):
        _seed(db_session)
        with patch("app.core.operating_status.settings.INACTIVE_REPOS", "bob/app"):
            active = list_runtimes(db_session, RuntimeFilter(operating="active"), today=_TODAY)
            inactive = list_runtimes(db_session, RuntimeFilter(operating="inactive"), today=_TODAY)
        assert "bob/app" not in {r.repo_full_name for r, _ in active}
        assert {r.repo_full_name for r, _ in inactive} == {"bob/app"}


class TestSummarizeRepos:
    def test_counts_all_rows_even_when_the_filter_asks_for_needs_action(self, db_session):
        """集計は「うち対応が必要な数」を別に数えるため、needs_action で行を減らさない。"""
        _seed(db_session)
        rows = summarize_repos(db_session, RuntimeFilter(needs_action=True), today=_TODAY)
        assert rows == [("alice/web", 2, 1), ("bob/app", 1, 1), ("alice/api", 1, 0)]
