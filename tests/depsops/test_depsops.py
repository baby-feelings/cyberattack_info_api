"""DEPSOPS（Dependabot PR自動運用）機能のテスト。

POST /admin/dependabot-ops・app.depsops.classify・app.depsops.github_client・
app.depsops.runner・app.core.notifications.notify_dependabot_ops のテストを含む。
外部HTTP通信（GitHub API）は全てモックする。
"""
import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

import httpx  # noqa: E402

from app.core.notifications import notify_dependabot_ops  # noqa: E402
from app.depsops.classify import classify_bump  # noqa: E402
from app.depsops.github_client import (  # noqa: E402
    get_pull_request,
    has_ci_workflows,
    list_open_dependabot_prs,
    merge_pull_request,
    request_rebase,
)
from app.depsops.runner import _process_pr, run_dependabot_ops  # noqa: E402

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


# ──────────────────────────────────────────────────────────────
# app.depsops.classify
# ──────────────────────────────────────────────────────────────


class TestClassifyBump:
    def test_minor_bump(self):
        assert classify_bump("chore(deps): bump lucide-react from 1.18.0 to 1.37.0") \
            == "minor_or_patch"

    def test_patch_bump(self):
        assert classify_bump("Bump webrick from 1.9.1 to 1.9.2") == "minor_or_patch"

    def test_major_bump(self):
        assert classify_bump("chore(deps-dev): Bump typescript from 6.0.3 to 7.0.2") == "major"

    def test_zero_x_minor_change_treated_as_major(self):
        """0.x系はminorの変化も破壊的変更扱いにする（semverの慣習）。"""
        assert classify_bump("Bump foo from 0.32.1 to 0.52.4") == "major"

    def test_requirement_style_with_operators(self):
        assert classify_bump(
            "chore(deps): Update pyyaml requirement from >=6.0.2 to >=6.0.3"
        ) == "minor_or_patch"

    def test_no_version_pattern_is_unknown(self):
        assert classify_bump(
            "chore(deps): Bump react-dom and @types/react-dom in /dashboard"
        ) == "unknown"

    def test_non_numeric_version_in_from_to_is_unknown(self):
        """"from X to Y" は一致するが、Xが数値バージョンでないケース。"""
        assert classify_bump("Bump foo from latest to stable") == "unknown"


# ──────────────────────────────────────────────────────────────
# app.depsops.github_client
# ──────────────────────────────────────────────────────────────


class TestListOpenDependabotPrs:
    def test_filters_to_dependabot_author(self):
        prs = [
            {"number": 1, "title": "bump x", "user": {"login": "dependabot[bot]"}},
            {"number": 2, "title": "feat: y", "user": {"login": "someone"}},
        ]
        mock_client = _mock_httpx_client(get_return=_mock_response(prs))
        with patch("app.depsops.github_client.httpx.Client", return_value=mock_client):
            result = list_open_dependabot_prs("owner", "repo", "token")
        assert [pr["number"] for pr in result] == [1]


class TestGetPullRequest:
    def test_returns_detail(self):
        mock_client = _mock_httpx_client(
            get_return=_mock_response({"number": 1, "mergeable_state": "clean"})
        )
        with patch("app.depsops.github_client.httpx.Client", return_value=mock_client):
            result = get_pull_request("owner", "repo", 1, "token")
        assert result["mergeable_state"] == "clean"


class TestMergePullRequest:
    def test_merges_and_deletes_branch(self):
        mock_client = _mock_httpx_client(
            put_return=_mock_response({"merged": True}),
            get_return=_mock_response({"head": {"ref": "dependabot/npm/foo"}}),
            delete_return=_mock_response({}),
        )
        with patch("app.depsops.github_client.httpx.Client", return_value=mock_client):
            result = merge_pull_request("owner", "repo", 1, "token")
        assert result == {"merged": True}
        mock_client.delete.assert_called_once()
        assert "dependabot/npm/foo" in mock_client.delete.call_args[0][0]

    def test_branch_delete_failure_does_not_raise(self):
        mock_client = _mock_httpx_client(
            put_return=_mock_response({"merged": True}),
            get_return=_mock_response({"head": {"ref": "dependabot/npm/foo"}}),
        )
        mock_client.delete = MagicMock(
            side_effect=httpx.HTTPStatusError("404", request=MagicMock(), response=MagicMock())
        )
        with patch("app.depsops.github_client.httpx.Client", return_value=mock_client):
            result = merge_pull_request("owner", "repo", 1, "token")
        assert result == {"merged": True}


class TestRequestRebase:
    def test_posts_rebase_comment(self):
        mock_client = _mock_httpx_client(post_return=_mock_response({}))
        with patch("app.depsops.github_client.httpx.Client", return_value=mock_client):
            request_rebase("owner", "repo", 1, "token")
        assert mock_client.post.call_args.kwargs["json"] == {"body": "@dependabot rebase"}


class TestHasCiWorkflows:
    def test_returns_true_when_workflows_exist(self):
        mock_client = _mock_httpx_client(
            get_return=_mock_response([{"name": "ci.yml"}], status_code=200)
        )
        with patch("app.depsops.github_client.httpx.Client", return_value=mock_client):
            assert has_ci_workflows("owner", "repo", "token") is True

    def test_returns_false_on_404(self):
        resp = _mock_response({"message": "Not Found"}, status_code=404)
        mock_client = _mock_httpx_client(get_return=resp)
        with patch("app.depsops.github_client.httpx.Client", return_value=mock_client):
            assert has_ci_workflows("owner", "repo", "token") is False


# ──────────────────────────────────────────────────────────────
# app.depsops.runner
# ──────────────────────────────────────────────────────────────


class TestProcessPr:
    def _pr(self, title="Bump x from 1.0.0 to 1.0.1", number=1):
        return {"number": number, "title": title}

    def test_dirty_requests_rebase(self):
        with patch(
            "app.depsops.runner.get_pull_request", return_value={"mergeable_state": "dirty"},
        ), patch("app.depsops.runner.request_rebase") as mock_rebase, \
           patch("app.depsops.runner.merge_pull_request") as mock_merge:
            action, item = _process_pr("u/r", "u", "r", self._pr(), True, "token")
        assert action == "flagged"
        assert "リベース" in item["reason"]
        mock_rebase.assert_called_once()
        mock_merge.assert_not_called()

    def test_no_ci_flags_without_merging(self):
        with patch(
            "app.depsops.runner.get_pull_request", return_value={"mergeable_state": "clean"},
        ), patch("app.depsops.runner.merge_pull_request") as mock_merge:
            action, item = _process_pr("u/r", "u", "r", self._pr(), False, "token")
        assert action == "flagged"
        assert "CI未設定" in item["reason"]
        mock_merge.assert_not_called()

    def test_major_bump_flags_without_merging(self):
        pr = self._pr(title="Bump x from 1.0.0 to 2.0.0")
        with patch(
            "app.depsops.runner.get_pull_request", return_value={"mergeable_state": "clean"},
        ), patch("app.depsops.runner.merge_pull_request") as mock_merge:
            action, item = _process_pr("u/r", "u", "r", pr, True, "token")
        assert action == "flagged"
        assert "メジャー" in item["reason"]
        mock_merge.assert_not_called()

    def test_unknown_bump_flags_without_merging(self):
        pr = self._pr(title="Bump x and y in /dashboard")
        with patch(
            "app.depsops.runner.get_pull_request", return_value={"mergeable_state": "clean"},
        ), patch("app.depsops.runner.merge_pull_request") as mock_merge:
            action, item = _process_pr("u/r", "u", "r", pr, True, "token")
        assert action == "flagged"
        assert "判定不可" in item["reason"]
        mock_merge.assert_not_called()

    def test_unstable_state_flags_without_merging(self):
        with patch(
            "app.depsops.runner.get_pull_request", return_value={"mergeable_state": "unstable"},
        ), patch("app.depsops.runner.merge_pull_request") as mock_merge:
            action, item = _process_pr("u/r", "u", "r", self._pr(), True, "token")
        assert action == "flagged"
        mock_merge.assert_not_called()

    def test_clean_minor_with_ci_merges(self):
        with patch(
            "app.depsops.runner.get_pull_request", return_value={"mergeable_state": "clean"},
        ), patch("app.depsops.runner.merge_pull_request") as mock_merge:
            action, item = _process_pr("u/r", "u", "r", self._pr(), True, "token")
        assert action == "merged"
        assert item["repo_full_name"] == "u/r"
        mock_merge.assert_called_once()


class TestRunDependabotOps:
    def test_success_path_aggregates_results(self, db_session):
        repos = [{"full_name": "u/r1"}, {"full_name": "u/r2"}]
        prs = [{"number": 1, "title": "Bump x from 1.0.0 to 1.0.1"}]
        with patch("app.depsops.runner.list_target_repos", return_value=repos), \
             patch("app.depsops.runner.list_open_dependabot_prs", return_value=prs), \
             patch("app.depsops.runner.has_ci_workflows", return_value=True), \
             patch(
                 "app.depsops.runner.get_pull_request",
                 return_value={"mergeable_state": "clean"},
             ), \
             patch("app.depsops.runner.merge_pull_request"), \
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
             patch(
                 "app.depsops.runner.get_pull_request",
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
             patch(
                 "app.depsops.runner.get_pull_request",
                 return_value={"mergeable_state": "clean"},
             ), \
             patch("app.depsops.runner.merge_pull_request") as mock_merge, \
             patch("app.depsops.runner.notify_dependabot_ops"):
            merged_count, flagged_count, error_count = run_dependabot_ops()
        assert (merged_count, flagged_count, error_count) == (0, 1, 0)
        mock_merge.assert_not_called()

    def test_fatal_error_writes_error_log_and_reraises(self, db_session):
        import pytest
        with patch(
            "app.depsops.runner.list_target_repos", side_effect=RuntimeError("GitHub API down"),
        ), patch("app.depsops.runner.notify_error") as mock_notify_error:
            with pytest.raises(RuntimeError):
                run_dependabot_ops()
        mock_notify_error.assert_called_once()


# ──────────────────────────────────────────────────────────────
# app.core.notifications.notify_dependabot_ops
# ──────────────────────────────────────────────────────────────


class TestNotifyDependabotOps:
    def test_skips_when_no_webhook(self):
        merged = [{"repo_full_name": "u/r", "pr_number": 1, "title": "bump x"}]
        with patch("app.core.notifications.settings.SLACK_WEBHOOK_URL", ""):
            with patch("app.core.notifications._send_slack") as mock_send:
                notify_dependabot_ops(merged, [])
        mock_send.assert_not_called()

    def test_skips_when_both_empty(self):
        with patch("app.core.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/x"):
            with patch("app.core.notifications._send_slack") as mock_send:
                notify_dependabot_ops([], [])
        mock_send.assert_not_called()

    def test_includes_merged_and_flagged_sections(self):
        merged = [{"repo_full_name": "u/r1", "pr_number": 1, "title": "bump x"}]
        flagged = [
            {"repo_full_name": "u/r2", "pr_number": 2, "title": "bump y", "reason": "メジャー"},
        ]
        with patch("app.core.notifications.settings.SLACK_WEBHOOK_URL", "https://hooks.slack.com/x"):
            with patch("app.core.notifications._send_slack") as mock_send:
                notify_dependabot_ops(merged, flagged)
        message = mock_send.call_args[0][0]
        assert "u/r1" in message and "bump x" in message
        assert "u/r2" in message and "メジャー" in message


# ──────────────────────────────────────────────────────────────
# POST /admin/dependabot-ops
# ──────────────────────────────────────────────────────────────


class TestAdminDependabotOps:
    def test_requires_auth(self, client):
        res = client.post("/admin/dependabot-ops")
        assert res.status_code == 403

    def test_trigger_returns_202(self, client):
        with patch("app.main.run_dependabot_ops", return_value=(0, 0, 0)):
            res = client.post("/admin/dependabot-ops", headers=HEADERS)
        assert res.status_code == 202
        assert "background" in res.json()["message"].lower()
