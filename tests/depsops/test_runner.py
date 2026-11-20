"""`run_dependabot_ops`（リポジトリを巡回して、PR を判定・マージする本体）のテスト。
"""
import os
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

import httpx  # noqa: E402

from app.crawler_logs.models import CrawlerLog  # noqa: E402
from app.depsops.models import DependabotPrLog  # noqa: E402
from app.depsops.runner import run_dependabot_ops  # noqa: E402

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


class TestRunDependabotOpsDeduplication:
    """Issue #239: APScheduler・GitHub Actionsの二重トリガー対策。"""

    def test_skips_when_already_succeeded_recently(self, db_session):
        db_session.add(DependabotPrLog(
            repo_full_name="u/r", pr_number=1, title="t", action="merged",
            processed_at=datetime.now(UTC),
        ))
        db_session.add(CrawlerLog(
            crawler_type="DEPSOPS", status="success",
            started_at=datetime.now(UTC), finished_at=datetime.now(UTC),
            duration_seconds=1.0,
        ))
        db_session.commit()

        with patch("app.depsops.runner.list_target_repos") as mock_list_repos:
            result = run_dependabot_ops()

        assert result == (0, 0, 0)
        mock_list_repos.assert_not_called()

    def test_force_bypasses_the_skip(self, db_session):
        db_session.add(CrawlerLog(
            crawler_type="DEPSOPS", status="success",
            started_at=datetime.now(UTC), finished_at=datetime.now(UTC),
            duration_seconds=1.0,
        ))
        db_session.commit()

        with patch("app.depsops.runner.list_target_repos", return_value=[]), \
             patch("app.depsops.runner.notify_dependabot_ops"):
            merged_count, flagged_count, error_count = run_dependabot_ops(force=True)

        assert (merged_count, flagged_count, error_count) == (0, 0, 0)


class TestRunDependabotOps:
    def test_success_path_aggregates_results(self, db_session):
        repos = [{"full_name": "u/r1"}, {"full_name": "u/r2"}]
        prs = [{"number": 1, "title": "Bump x from 1.0.0 to 1.0.1"}]
        with patch("app.depsops.runner.list_target_repos", return_value=repos), \
             patch("app.depsops.runner.list_open_dependabot_prs", return_value=prs), \
             patch("app.depsops.runner.has_ci_workflows", return_value=True), \
             patch("app.depsops.runner.list_open_dependabot_alerts", return_value=[]), \
             patch(
                 "app.depsops.pr_judge.get_pull_request",
                 return_value={"mergeable_state": "clean"},
             ), \
             patch("app.depsops.pr_judge.merge_pull_request"), \
             patch("app.depsops.runner.notify_dependabot_ops") as mock_notify:
            merged_count, flagged_count, error_count = run_dependabot_ops()

        assert merged_count == 2  # r1・r2 それぞれ1件ずつマージ
        assert flagged_count == 0
        assert error_count == 0
        mock_notify.assert_called_once()

    def test_no_open_prs_skips_repo(self, db_session):
        repos = [{"full_name": "u/r1"}]
        with patch("app.depsops.runner.list_target_repos", return_value=repos), \
             patch("app.depsops.runner.list_open_dependabot_prs", return_value=[]), \
             patch("app.depsops.runner.has_ci_workflows") as mock_has_ci, \
             patch("app.depsops.runner.notify_dependabot_ops"):
            merged_count, flagged_count, error_count = run_dependabot_ops()
        assert (merged_count, flagged_count, error_count) == (0, 0, 0)
        mock_has_ci.assert_not_called()

    def test_list_prs_failure_counts_as_error(self, db_session):
        repos = [{"full_name": "u/r1"}]
        with patch("app.depsops.runner.list_target_repos", return_value=repos), \
             patch(
                 "app.depsops.runner.list_open_dependabot_prs",
                 side_effect=httpx.HTTPStatusError(
                     "500", request=MagicMock(), response=MagicMock(),
                 ),
             ), \
             patch("app.depsops.runner.notify_dependabot_ops"):
            merged_count, flagged_count, error_count = run_dependabot_ops()
        assert (merged_count, flagged_count, error_count) == (0, 0, 1)

    def test_process_pr_failure_counts_as_error(self, db_session):
        repos = [{"full_name": "u/r1"}]
        prs = [{"number": 1, "title": "Bump x from 1.0.0 to 1.0.1"}]
        with patch("app.depsops.runner.list_target_repos", return_value=repos), \
             patch("app.depsops.runner.list_open_dependabot_prs", return_value=prs), \
             patch("app.depsops.runner.has_ci_workflows", return_value=True), \
             patch("app.depsops.runner.list_open_dependabot_alerts", return_value=[]), \
             patch(
                 "app.depsops.pr_judge.get_pull_request",
                 side_effect=httpx.HTTPStatusError(
                     "500", request=MagicMock(), response=MagicMock(),
                 ),
             ), \
             patch("app.depsops.runner.notify_dependabot_ops"):
            merged_count, flagged_count, error_count = run_dependabot_ops()
        assert (merged_count, flagged_count, error_count) == (0, 0, 1)

    def test_flagged_pr_is_aggregated(self, db_session):
        repos = [{"full_name": "u/r1"}]
        prs = [{"number": 1, "title": "Bump x from 1.0.0 to 2.0.0"}]  # メジャー
        with patch("app.depsops.runner.list_target_repos", return_value=repos), \
             patch("app.depsops.runner.list_open_dependabot_prs", return_value=prs), \
             patch("app.depsops.runner.has_ci_workflows", return_value=True), \
             patch("app.depsops.runner.list_open_dependabot_alerts", return_value=[]), \
             patch(
                 "app.depsops.pr_judge.get_pull_request",
                 return_value={"mergeable_state": "clean"},
             ), \
             patch("app.depsops.pr_judge.merge_pull_request") as mock_merge, \
             patch("app.depsops.runner.notify_dependabot_ops"):
            merged_count, flagged_count, error_count = run_dependabot_ops()
        assert (merged_count, flagged_count, error_count) == (0, 1, 0)
        mock_merge.assert_not_called()

    def test_fatal_error_writes_error_log_and_reraises(self, db_session):
        import pytest
        with patch(
            "app.depsops.runner.list_target_repos", side_effect=RuntimeError("GitHub API down"),
        ), patch("app.core.runner.crawler_runner.notify_error") as mock_notify_error:
            with pytest.raises(RuntimeError):
                run_dependabot_ops()
        mock_notify_error.assert_called_once()

    def test_persists_merged_and_flagged_prs_to_db(self, db_session):
        """マージ済み・要確認いずれの PR も DependabotPrLog に記録されること。"""
        repos = [{"full_name": "u/r1"}]
        prs = [
            {"number": 1, "title": "Bump x from 1.0.0 to 1.0.1"},  # minor → merged
            {"number": 2, "title": "Bump y from 1.0.0 to 2.0.0"},  # major → flagged
        ]

        def _get_pr(repo, number):
            return {"mergeable_state": "clean"}

        with patch("app.depsops.runner.list_target_repos", return_value=repos), \
             patch("app.depsops.runner.list_open_dependabot_prs", return_value=prs), \
             patch("app.depsops.runner.has_ci_workflows", return_value=True), \
             patch("app.depsops.runner.list_open_dependabot_alerts", return_value=[]), \
             patch("app.depsops.pr_judge.get_pull_request", side_effect=_get_pr), \
             patch("app.depsops.pr_judge.merge_pull_request"), \
             patch("app.depsops.runner.notify_dependabot_ops"):
            run_dependabot_ops()

        rows = db_session.query(DependabotPrLog).order_by(DependabotPrLog.pr_number).all()
        assert [(r.pr_number, r.action) for r in rows] == [(1, "merged"), (2, "flagged")]
        assert rows[0].reason is None
        assert "メジャー" in rows[1].reason

    def test_deletes_logs_of_pr_resolved_outside_depsops(self, db_session):
        """CI未設定等で過去にflagged記録したPRが、今回のスキャンでOpen PR一覧に
        含まれなくなった場合（Dependabotの自動クローズ・手動マージ等）、そのPRの
        履歴行が全削除され、以後「未解決」件数から除外されること。"""
        db_session.add(DependabotPrLog(
            repo_full_name="u/r1", pr_number=99, title="bump old from 1.0.0 to 1.0.1",
            action="flagged", reason="CI未設定のリポジトリ",
            processed_at=datetime.now(UTC) - timedelta(days=1),
        ))
        db_session.commit()

        repos = [{"full_name": "u/r1"}]
        with patch("app.depsops.runner.list_target_repos", return_value=repos), \
             patch("app.depsops.runner.list_open_dependabot_prs", return_value=[]), \
             patch("app.depsops.runner.notify_dependabot_ops"):
            run_dependabot_ops()

        assert db_session.query(DependabotPrLog).filter_by(pr_number=99).count() == 0

    def test_does_not_resolve_pr_that_is_still_open(self, db_session):
        """過去にflagged記録したPRが今回もOpen一覧に含まれる場合は"closed"にしないこと。"""
        db_session.add(DependabotPrLog(
            repo_full_name="u/r1", pr_number=1, title="Bump x from 1.0.0 to 2.0.0",
            action="flagged", reason="メジャーバージョンアップ",
            processed_at=datetime.now(UTC) - timedelta(days=1),
        ))
        db_session.commit()

        repos = [{"full_name": "u/r1"}]
        prs = [{"number": 1, "title": "Bump x from 1.0.0 to 2.0.0"}]  # 引き続きOpen・メジャー
        with patch("app.depsops.runner.list_target_repos", return_value=repos), \
             patch("app.depsops.runner.list_open_dependabot_prs", return_value=prs), \
             patch("app.depsops.runner.has_ci_workflows", return_value=True), \
             patch("app.depsops.runner.list_open_dependabot_alerts", return_value=[]), \
             patch(
                 "app.depsops.pr_judge.get_pull_request",
                 return_value={"mergeable_state": "clean"},
             ), \
             patch("app.depsops.runner.notify_dependabot_ops"):
            run_dependabot_ops()

        rows = db_session.query(DependabotPrLog).filter_by(pr_number=1).all()
        assert all(r.action == "flagged" for r in rows)
