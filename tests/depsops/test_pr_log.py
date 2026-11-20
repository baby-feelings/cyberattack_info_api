"""PR 判定ログの記録・整理・解消済みの検知・古い記録の削除のテスト。
"""
import os
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")


from app.depsops.models import DependabotPrLog  # noqa: E402
from app.depsops.pr_log_repository import PrLogRepository  # noqa: E402
from app.depsops.pr_log_retention import PrLogRetention  # noqa: E402

TEST_API_KEY = "test-api-key-for-pytest"
HEADERS = {"X-API-KEY": TEST_API_KEY}


def _mock_httpx_client(get_return=None, put_return=None, post_return=None, delete_return=None):
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    if get_return is not None:
        mock_client.get = MagicMock(return_value=get_return)
    if put_return is not None:
        mock_client.put = MagicMock(return_value=put_return)
    if post_return is not None:
        mock_client.post = MagicMock(return_value=post_return)
    if delete_return is not None:
        mock_client.delete = MagicMock(return_value=delete_return)
    return mock_client


def _mock_response(json_data, status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.raise_for_status = MagicMock()
    resp.json.return_value = json_data
    return resp


class TestRecordPrLogs:
    def test_writes_one_row_per_pr_with_correct_action_and_reason(self, db_session):
        merged = [{"repo_full_name": "u/r", "pr_number": 1, "title": "bump x"}]
        flagged = [
            {"repo_full_name": "u/r", "pr_number": 2, "title": "bump y", "reason": "メジャー"},
        ]
        processed_at = datetime(2026, 6, 1, tzinfo=UTC)

        PrLogRepository(db_session).record(merged, flagged, processed_at)

        rows = db_session.query(DependabotPrLog).order_by(DependabotPrLog.pr_number).all()
        assert len(rows) == 2
        assert rows[0].action == "merged" and rows[0].reason is None
        assert rows[1].action == "flagged" and rows[1].reason == "メジャー"

    def test_persists_is_security_update_flag(self, db_session):
        merged = [{
            "repo_full_name": "u/r", "pr_number": 1, "title": "bump x",
            "is_security_update": True,
        }]
        flagged = [{
            "repo_full_name": "u/r", "pr_number": 2, "title": "bump y", "reason": "メジャー",
            "is_security_update": False,
        }]
        processed_at = datetime(2026, 6, 1, tzinfo=UTC)

        PrLogRepository(db_session).record(merged, flagged, processed_at)

        rows = db_session.query(DependabotPrLog).order_by(DependabotPrLog.pr_number).all()
        assert rows[0].is_security_update is True
        assert rows[1].is_security_update is False

    def test_missing_is_security_update_key_defaults_to_none(self, db_session):
        """alert取得自体に失敗したケース: キーが無くても例外にならずNoneになる。"""
        merged = [{"repo_full_name": "u/r", "pr_number": 1, "title": "bump x"}]
        processed_at = datetime(2026, 6, 1, tzinfo=UTC)

        PrLogRepository(db_session).record(merged, [], processed_at)

        row = db_session.query(DependabotPrLog).filter_by(pr_number=1).first()
        assert row.is_security_update is None

    def test_persists_compatibility_badge_url(self, db_session):
        merged = [{
            "repo_full_name": "u/r", "pr_number": 1, "title": "bump x",
            "compatibility_badge_url": "https://dependabot-badges.githubapp.com/badges/x",
        }]
        processed_at = datetime(2026, 6, 1, tzinfo=UTC)

        PrLogRepository(db_session).record(merged, [], processed_at)

        row = db_session.query(DependabotPrLog).filter_by(pr_number=1).first()
        assert row.compatibility_badge_url == "https://dependabot-badges.githubapp.com/badges/x"

    def test_resolved_prs_have_all_rows_deleted_but_merged_rows_are_kept(self, db_session):
        """resolved（DEPSOPS外の要因で解消済みと判定したPR）は全行が削除され、
        他PRの"merged"（自動マージの記録）は残ること。"""
        old = datetime(2026, 5, 31, tzinfo=UTC)
        for n in (3, 3, 4):
            db_session.add(DependabotPrLog(
                repo_full_name="u/r", pr_number=n, title="bump", action="flagged",
                reason="CI未設定", processed_at=old,
            ))
        db_session.add(DependabotPrLog(
            repo_full_name="u/r", pr_number=5, title="bump", action="merged",
            processed_at=old,
        ))
        db_session.commit()
        resolved = [{"repo_full_name": "u/r", "pr_number": 3, "title": "bump z"}]

        PrLogRepository(db_session).record(
            [], [], datetime(2026, 6, 1, tzinfo=UTC), resolved=resolved,
        )

        assert db_session.query(DependabotPrLog).filter_by(pr_number=3).count() == 0
        assert db_session.query(DependabotPrLog).filter_by(pr_number=4).count() == 1
        assert db_session.query(DependabotPrLog).filter_by(pr_number=5).count() == 1
        assert db_session.query(DependabotPrLog).filter_by(action="closed").count() == 0

    def test_unchanged_flagged_pr_updates_existing_row_instead_of_appending(self, db_session):
        """同じ理由で「要確認」のまま続くPRは、行を追記せず既存行の判定日時を更新すること。"""
        flagged = [{
            "repo_full_name": "u/r", "pr_number": 2, "title": "bump y", "reason": "メジャー",
            "is_security_update": False,
        }]
        day1 = datetime(2026, 6, 1, tzinfo=UTC)
        day2 = datetime(2026, 6, 2, tzinfo=UTC)

        PrLogRepository(db_session).record([], flagged, day1)
        PrLogRepository(db_session).record([], flagged, day2)

        rows = db_session.query(DependabotPrLog).filter_by(pr_number=2).all()
        assert len(rows) == 1
        assert rows[0].processed_at.replace(tzinfo=UTC) == day2

    def test_flagged_pr_with_changed_reason_appends_new_row(self, db_session):
        """理由が変わった場合は状態変化の履歴として新しい行が追記されること。"""
        base = {"repo_full_name": "u/r", "pr_number": 2, "title": "bump y"}
        PrLogRepository(db_session).record(
            [], [{**base, "reason": "CI未設定"}],
            datetime(2026, 6, 1, tzinfo=UTC),
        )
        PrLogRepository(db_session).record(
            [], [{**base, "reason": "メジャーバージョンアップ"}],
            datetime(2026, 6, 2, tzinfo=UTC),
        )

        rows = db_session.query(DependabotPrLog).filter_by(pr_number=2).order_by(
            DependabotPrLog.processed_at,
        ).all()
        assert [r.reason for r in rows] == ["CI未設定", "メジャーバージョンアップ"]

    def test_flagged_after_merged_is_appended_not_merged_into_old_row(self, db_session):
        """直近の行が"merged"のPRが再度flaggedになった場合は新しい行として追記されること。"""
        base = {"repo_full_name": "u/r", "pr_number": 2, "title": "bump y"}
        PrLogRepository(db_session).record([base], [], datetime(2026, 6, 1, tzinfo=UTC))
        PrLogRepository(db_session).record(
            [], [{**base, "reason": "CI失敗"}],
            datetime(2026, 6, 2, tzinfo=UTC),
        )

        actions = [
            r.action for r in db_session.query(DependabotPrLog).filter_by(pr_number=2)
            .order_by(DependabotPrLog.processed_at).all()
        ]
        assert actions == ["merged", "flagged"]


class TestCleanupPrLogs:
    @staticmethod
    def _add(db, n, action, day, reason="CI未設定", repo="u/r", security=None):
        db.add(DependabotPrLog(
            repo_full_name=repo, pr_number=n, title="bump", action=action,
            reason=reason if action != "merged" else None, is_security_update=security,
            processed_at=datetime(2026, 9, day, tzinfo=UTC),
        ))

    def test_purge_legacy_closed_deletes_all_rows_of_closed_prs_only(self, db_session):
        self._add(db_session, 1, "flagged", 1)
        self._add(db_session, 1, "flagged", 2)
        self._add(db_session, 1, "closed", 3, reason="解消済み")
        self._add(db_session, 2, "flagged", 1)
        self._add(db_session, 3, "merged", 1)
        db_session.commit()

        deleted = PrLogRetention(db_session).purge_legacy_closed()

        assert deleted == 3
        remaining = sorted(
            (r.pr_number, r.action) for r in db_session.query(DependabotPrLog).all()
        )
        assert remaining == [(2, "flagged"), (3, "merged")]

    def test_purge_legacy_closed_keeps_pr_that_became_flagged_again(self, db_session):
        """closedの後に再びflaggedになったPRは最新状態がflaggedなので削除しないこと。"""
        self._add(db_session, 1, "closed", 1, reason="解消済み")
        self._add(db_session, 1, "flagged", 2)
        db_session.commit()

        assert PrLogRetention(db_session).purge_legacy_closed() == 0
        assert db_session.query(DependabotPrLog).count() == 2

    def test_collapse_keeps_only_latest_of_identical_consecutive_flagged_rows(self, db_session):
        for day in (1, 2, 3, 4):
            self._add(db_session, 1, "flagged", day)
        self._add(db_session, 2, "flagged", 1)
        db_session.commit()

        deleted = PrLogRetention(db_session).collapse_duplicate_flagged()

        assert deleted == 3
        rows = db_session.query(DependabotPrLog).filter_by(pr_number=1).all()
        assert len(rows) == 1
        assert rows[0].processed_at.replace(tzinfo=UTC).day == 4
        assert db_session.query(DependabotPrLog).filter_by(pr_number=2).count() == 1

    def test_collapse_preserves_history_when_reason_changes_in_between(self, db_session):
        """理由が変わった境目の行は履歴として残し、同一内容の連続分だけを集約すること。"""
        self._add(db_session, 1, "flagged", 1, reason="CI未設定")
        self._add(db_session, 1, "flagged", 2, reason="CI未設定")
        self._add(db_session, 1, "flagged", 3, reason="メジャー")
        self._add(db_session, 1, "flagged", 4, reason="メジャー")
        db_session.commit()

        assert PrLogRetention(db_session).collapse_duplicate_flagged() == 2
        days = sorted(
            r.processed_at.replace(tzinfo=UTC).day
            for r in db_session.query(DependabotPrLog).all()
        )
        assert days == [2, 4]

    def test_collapse_does_not_merge_across_different_prs_or_repos(self, db_session):
        self._add(db_session, 1, "flagged", 1, repo="u/a")
        self._add(db_session, 1, "flagged", 1, repo="u/b")
        self._add(db_session, 2, "flagged", 1, repo="u/a")
        db_session.commit()

        assert PrLogRetention(db_session).collapse_duplicate_flagged() == 0
        assert db_session.query(DependabotPrLog).count() == 3

    def test_collapse_does_not_touch_merged_rows(self, db_session):
        self._add(db_session, 1, "merged", 1)
        self._add(db_session, 1, "merged", 2)
        db_session.commit()

        assert PrLogRetention(db_session).collapse_duplicate_flagged() == 0

    def test_cleanup_is_idempotent(self, db_session):
        for day in (1, 2, 3):
            self._add(db_session, 1, "flagged", day)
        self._add(db_session, 2, "closed", 1, reason="解消済み")
        db_session.commit()

        PrLogRetention(db_session).cleanup()
        first = db_session.query(DependabotPrLog).count()
        PrLogRetention(db_session).cleanup()

        assert first == 1
        assert db_session.query(DependabotPrLog).count() == 1


class TestFindResolvedFlaggedPrs:
    def test_detects_pr_no_longer_open(self, db_session):
        """CI未設定リポジトリ等で過去にflagged記録したPRが、今回のOpen PR一覧に
        含まれなくなっていれば「DEPSOPS外の要因で解消済み」として検出すること。"""
        db_session.add(DependabotPrLog(
            repo_full_name="u/r1", pr_number=5, title="bump z from 1.0.0 to 2.0.0",
            action="flagged", reason="CI未設定のリポジトリ",
            processed_at=datetime(2026, 6, 1, tzinfo=UTC),
        ))
        db_session.commit()

        result = PrLogRepository(db_session).find_resolved_flagged("u/r1", open_pr_numbers=set())

        assert len(result) == 1
        assert result[0]["pr_number"] == 5
        assert result[0]["title"] == "bump z from 1.0.0 to 2.0.0"

    def test_ignores_pr_still_open(self, db_session):
        db_session.add(DependabotPrLog(
            repo_full_name="u/r1", pr_number=5, title="bump z",
            action="flagged", processed_at=datetime(2026, 6, 1, tzinfo=UTC),
        ))
        db_session.commit()

        result = PrLogRepository(db_session).find_resolved_flagged("u/r1", open_pr_numbers={5})

        assert result == []

    def test_ignores_already_merged_pr(self, db_session):
        db_session.add(DependabotPrLog(
            repo_full_name="u/r1", pr_number=5, title="bump z",
            action="merged", processed_at=datetime(2026, 6, 1, tzinfo=UTC),
        ))
        db_session.commit()

        result = PrLogRepository(db_session).find_resolved_flagged("u/r1", open_pr_numbers=set())

        assert result == []

    def test_uses_latest_state_when_multiple_rows_exist(self, db_session):
        """同一PRについて複数回判定履歴がある場合、最新の状態のみを見ること。"""
        db_session.add_all([
            DependabotPrLog(
                repo_full_name="u/r1", pr_number=5, title="bump z",
                action="flagged", processed_at=datetime(2026, 6, 1, tzinfo=UTC),
            ),
            DependabotPrLog(
                repo_full_name="u/r1", pr_number=5, title="bump z",
                action="merged", processed_at=datetime(2026, 6, 2, tzinfo=UTC),
            ),
        ])
        db_session.commit()

        result = PrLogRepository(db_session).find_resolved_flagged("u/r1", open_pr_numbers=set())

        assert result == []

    def test_ignores_other_repos(self, db_session):
        db_session.add(DependabotPrLog(
            repo_full_name="u/other", pr_number=5, title="bump z",
            action="flagged", processed_at=datetime(2026, 6, 1, tzinfo=UTC),
        ))
        db_session.commit()

        result = PrLogRepository(db_session).find_resolved_flagged("u/r1", open_pr_numbers=set())

        assert result == []


class TestDeleteOldDepsopsRecords:
    def test_deletes_only_records_older_than_retention_period(self, db_session):
        old = DependabotPrLog(
            repo_full_name="u/r", pr_number=1, title="old", action="merged",
            processed_at=datetime.now(UTC) - timedelta(days=200),
        )
        recent = DependabotPrLog(
            repo_full_name="u/r", pr_number=2, title="recent", action="merged",
            processed_at=datetime.now(UTC) - timedelta(days=1),
        )
        db_session.add_all([old, recent])
        db_session.commit()

        deleted = PrLogRetention(db_session).delete_expired()

        assert deleted == 1
        remaining = db_session.query(DependabotPrLog).all()
        assert [r.pr_number for r in remaining] == [2]
