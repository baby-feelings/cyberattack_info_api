"""DEPSOPS（Dependabot PR自動運用）機能のテスト。

POST /admin/dependabot-ops・app.depsops.classify・app.depsops.github_client・
app.depsops.runner・app.core.notifications.notify_dependabot_ops のテストを含む。
外部HTTP通信（GitHub API）は全てモックする。
"""
import os
from datetime import datetime, timedelta, timezone
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
    list_open_dependabot_alerts,
    list_open_dependabot_prs,
    merge_pull_request,
    request_rebase,
)
from app.depsops.models import DependabotPrLog  # noqa: E402
from app.depsops.runner import (  # noqa: E402
    _delete_old_depsops_records,
    _extract_compatibility_badge_url,
    _matches_security_alert,
    _process_pr,
    _record_pr_logs,
    run_dependabot_ops,
)

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


class TestListOpenDependabotAlerts:
    def test_returns_alert_list(self):
        alerts = [{"dependency": {"package": {"name": "requests"}}}]
        mock_client = _mock_httpx_client(get_return=_mock_response(alerts))
        with patch("app.depsops.github_client.httpx.Client", return_value=mock_client):
            result = list_open_dependabot_alerts("owner", "repo", "token")
        assert result == alerts
        call = mock_client.get.call_args
        assert call.args[0].endswith("/dependabot/alerts")
        assert call.kwargs["params"]["state"] == "open"

    def test_raises_on_http_error(self):
        resp = MagicMock()
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "403", request=MagicMock(), response=MagicMock(),
        )
        mock_client = _mock_httpx_client(get_return=resp)
        import pytest
        with patch("app.depsops.github_client.httpx.Client", return_value=mock_client):
            with pytest.raises(httpx.HTTPStatusError):
                list_open_dependabot_alerts("owner", "repo", "token")


# ──────────────────────────────────────────────────────────────
# app.depsops.runner
# ──────────────────────────────────────────────────────────────


class TestMatchesSecurityAlert:
    def test_none_alert_packages_means_unknown(self):
        assert _matches_security_alert("Bump requests from 1.0 to 2.0", None) is None

    def test_matching_package_returns_true(self):
        result = _matches_security_alert(
            "Bump requests from 1.0 to 2.0", {"requests", "flask"},
        )
        assert result is True

    def test_no_matching_package_returns_false(self):
        result = _matches_security_alert(
            "Bump requests from 1.0 to 2.0", {"flask", "django"},
        )
        assert result is False

    def test_empty_alert_set_returns_false(self):
        assert _matches_security_alert("Bump requests from 1.0 to 2.0", set()) is False

    def test_matches_case_insensitively(self):
        result = _matches_security_alert("Bump REQUESTS from 1.0 to 2.0", {"requests"})
        assert result is True

    def test_does_not_match_substring_of_a_different_package(self):
        """"requests" は "requests_toolbelt" の一部として誤マッチしないこと。"""
        result = _matches_security_alert(
            "Bump requests_toolbelt from 1.0 to 2.0", {"requests"},
        )
        assert result is False


class TestExtractCompatibilityBadgeUrl:
    def test_extracts_badge_url_from_pr_body(self):
        body = (
            "Bumps google-genai from 2.19.0 to 2.20.0.\n\n"
            "[![Dependabot compatibility score]"
            "(https://dependabot-badges.githubapp.com/badges/compatibility_score"
            "?dependency-name=google-genai&package-manager=pip"
            "&previous-version=2.19.0&new-version=2.20.0)]"
            "(https://docs.github.com/en/github/managing-security-vulnerabilities/"
            "about-dependabot-security-updates#about-compatibility-scores)"
        )
        url = _extract_compatibility_badge_url(body)
        assert url == (
            "https://dependabot-badges.githubapp.com/badges/compatibility_score"
            "?dependency-name=google-genai&package-manager=pip"
            "&previous-version=2.19.0&new-version=2.20.0"
        )

    def test_returns_none_when_badge_absent(self):
        """範囲指定の requirement 更新PR等、バッジが埋め込まれないケース。"""
        body = "Updates the requirements on foo to permit the latest version."
        assert _extract_compatibility_badge_url(body) is None

    def test_returns_none_for_empty_body(self):
        assert _extract_compatibility_badge_url(None) is None
        assert _extract_compatibility_badge_url("") is None


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
        assert item["is_security_update"] is None  # alert_package_names未指定時
        mock_merge.assert_called_once()

    def test_records_security_update_flag_when_alert_matches(self):
        pr = self._pr(title="Bump requests from 1.0.0 to 1.0.1")
        with patch(
            "app.depsops.runner.get_pull_request", return_value={"mergeable_state": "clean"},
        ), patch("app.depsops.runner.merge_pull_request"):
            action, item = _process_pr(
                "u/r", "u", "r", pr, True, "token", alert_package_names={"requests"},
            )
        assert action == "merged"
        assert item["is_security_update"] is True

    def test_records_security_update_false_when_no_alert_matches(self):
        pr = self._pr(title="Bump requests from 1.0.0 to 1.0.1")
        with patch(
            "app.depsops.runner.get_pull_request", return_value={"mergeable_state": "clean"},
        ), patch("app.depsops.runner.merge_pull_request"):
            action, item = _process_pr(
                "u/r", "u", "r", pr, True, "token", alert_package_names=set(),
            )
        assert action == "merged"
        assert item["is_security_update"] is False

    def test_extracts_compatibility_badge_url_from_pr_detail_body(self):
        pr = self._pr(title="Bump requests from 1.0.0 to 1.0.1")
        detail = {
            "mergeable_state": "clean",
            "body": (
                "[![Dependabot compatibility score]"
                "(https://dependabot-badges.githubapp.com/badges/compatibility_score"
                "?dependency-name=requests&package-manager=pip"
                "&previous-version=1.0.0&new-version=1.0.1)](https://docs.github.com/x)"
            ),
        }
        with patch("app.depsops.runner.get_pull_request", return_value=detail), \
             patch("app.depsops.runner.merge_pull_request"):
            action, item = _process_pr("u/r", "u", "r", pr, True, "token")
        assert action == "merged"
        assert item["compatibility_badge_url"] == (
            "https://dependabot-badges.githubapp.com/badges/compatibility_score"
            "?dependency-name=requests&package-manager=pip"
            "&previous-version=1.0.0&new-version=1.0.1"
        )

    def test_compatibility_badge_url_is_none_when_absent_from_body(self):
        with patch(
            "app.depsops.runner.get_pull_request",
            return_value={"mergeable_state": "clean", "body": "no badge here"},
        ), patch("app.depsops.runner.merge_pull_request"):
            action, item = _process_pr("u/r", "u", "r", self._pr(), True, "token")
        assert action == "merged"
        assert item["compatibility_badge_url"] is None


class TestRunDependabotOps:
    def test_success_path_aggregates_results(self, db_session):
        repos = [{"full_name": "u/r1"}, {"full_name": "u/r2"}]
        prs = [{"number": 1, "title": "Bump x from 1.0.0 to 1.0.1"}]
        with patch("app.depsops.runner.list_target_repos", return_value=repos), \
             patch("app.depsops.runner.list_open_dependabot_prs", return_value=prs), \
             patch("app.depsops.runner.has_ci_workflows", return_value=True), \
             patch("app.depsops.runner.list_open_dependabot_alerts", return_value=[]), \
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
             patch("app.depsops.runner.list_open_dependabot_alerts", return_value=[]), \
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
             patch("app.depsops.runner.list_open_dependabot_alerts", return_value=[]), \
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

    def test_persists_merged_and_flagged_prs_to_db(self, db_session):
        """マージ済み・要確認いずれの PR も DependabotPrLog に記録されること。"""
        repos = [{"full_name": "u/r1"}]
        prs = [
            {"number": 1, "title": "Bump x from 1.0.0 to 1.0.1"},  # minor → merged
            {"number": 2, "title": "Bump y from 1.0.0 to 2.0.0"},  # major → flagged
        ]

        def _get_pr(owner, repo, number, token):
            return {"mergeable_state": "clean"}

        with patch("app.depsops.runner.list_target_repos", return_value=repos), \
             patch("app.depsops.runner.list_open_dependabot_prs", return_value=prs), \
             patch("app.depsops.runner.has_ci_workflows", return_value=True), \
             patch("app.depsops.runner.list_open_dependabot_alerts", return_value=[]), \
             patch("app.depsops.runner.get_pull_request", side_effect=_get_pr), \
             patch("app.depsops.runner.merge_pull_request"), \
             patch("app.depsops.runner.notify_dependabot_ops"):
            run_dependabot_ops()

        rows = db_session.query(DependabotPrLog).order_by(DependabotPrLog.pr_number).all()
        assert [(r.pr_number, r.action) for r in rows] == [(1, "merged"), (2, "flagged")]
        assert rows[0].reason is None
        assert "メジャー" in rows[1].reason


class TestRecordPrLogs:
    def test_writes_one_row_per_pr_with_correct_action_and_reason(self, db_session):
        merged = [{"repo_full_name": "u/r", "pr_number": 1, "title": "bump x"}]
        flagged = [
            {"repo_full_name": "u/r", "pr_number": 2, "title": "bump y", "reason": "メジャー"},
        ]
        processed_at = datetime(2026, 6, 1, tzinfo=timezone.utc)

        _record_pr_logs(db_session, merged, flagged, processed_at)

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
        processed_at = datetime(2026, 6, 1, tzinfo=timezone.utc)

        _record_pr_logs(db_session, merged, flagged, processed_at)

        rows = db_session.query(DependabotPrLog).order_by(DependabotPrLog.pr_number).all()
        assert rows[0].is_security_update is True
        assert rows[1].is_security_update is False

    def test_missing_is_security_update_key_defaults_to_none(self, db_session):
        """alert取得自体に失敗したケース: キーが無くても例外にならずNoneになる。"""
        merged = [{"repo_full_name": "u/r", "pr_number": 1, "title": "bump x"}]
        processed_at = datetime(2026, 6, 1, tzinfo=timezone.utc)

        _record_pr_logs(db_session, merged, [], processed_at)

        row = db_session.query(DependabotPrLog).filter_by(pr_number=1).first()
        assert row.is_security_update is None

    def test_persists_compatibility_badge_url(self, db_session):
        merged = [{
            "repo_full_name": "u/r", "pr_number": 1, "title": "bump x",
            "compatibility_badge_url": "https://dependabot-badges.githubapp.com/badges/x",
        }]
        processed_at = datetime(2026, 6, 1, tzinfo=timezone.utc)

        _record_pr_logs(db_session, merged, [], processed_at)

        row = db_session.query(DependabotPrLog).filter_by(pr_number=1).first()
        assert row.compatibility_badge_url == "https://dependabot-badges.githubapp.com/badges/x"


class TestDeleteOldDepsopsRecords:
    def test_deletes_only_records_older_than_retention_period(self, db_session):
        old = DependabotPrLog(
            repo_full_name="u/r", pr_number=1, title="old", action="merged",
            processed_at=datetime.now(timezone.utc) - timedelta(days=200),
        )
        recent = DependabotPrLog(
            repo_full_name="u/r", pr_number=2, title="recent", action="merged",
            processed_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        db_session.add_all([old, recent])
        db_session.commit()

        deleted = _delete_old_depsops_records(db_session)

        assert deleted == 1
        remaining = db_session.query(DependabotPrLog).all()
        assert [r.pr_number for r in remaining] == [2]


# ──────────────────────────────────────────────────────────────
# GET /api/depsops
# ──────────────────────────────────────────────────────────────


class TestListDepsops:
    def test_requires_auth(self, client):
        res = client.get("/api/depsops")
        assert res.status_code == 403

    def test_returns_recent_prs_sorted_desc(self, client, db_session):
        db_session.add_all([
            DependabotPrLog(
                repo_full_name="u/r1", pr_number=1, title="bump a", action="merged",
                processed_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
            ),
            DependabotPrLog(
                repo_full_name="u/r2", pr_number=2, title="bump b", action="flagged",
                reason="メジャー", processed_at=datetime(2026, 6, 2, tzinfo=timezone.utc),
            ),
        ])
        db_session.commit()

        res = client.get("/api/depsops", headers=HEADERS)

        assert res.status_code == 200
        body = res.json()
        assert body["total"] == 2
        assert [item["pr_number"] for item in body["data"]] == [2, 1]
        assert body["data"][0]["reason"] == "メジャー"

    def test_filters_by_action(self, client, db_session):
        db_session.add_all([
            DependabotPrLog(
                repo_full_name="u/r1", pr_number=1, title="bump a", action="merged",
                processed_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
            ),
            DependabotPrLog(
                repo_full_name="u/r1", pr_number=2, title="bump b", action="flagged",
                reason="メジャー", processed_at=datetime(2026, 6, 2, tzinfo=timezone.utc),
            ),
        ])
        db_session.commit()

        res = client.get("/api/depsops?action=flagged", headers=HEADERS)

        assert res.status_code == 200
        body = res.json()
        assert body["total"] == 1
        assert body["data"][0]["action"] == "flagged"

    def test_filters_by_repo(self, client, db_session):
        db_session.add_all([
            DependabotPrLog(
                repo_full_name="u/r1", pr_number=1, title="bump a", action="merged",
                processed_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
            ),
            DependabotPrLog(
                repo_full_name="u/r2", pr_number=1, title="bump a", action="merged",
                processed_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
            ),
        ])
        db_session.commit()

        res = client.get("/api/depsops?repo=u/r2", headers=HEADERS)

        assert res.status_code == 200
        body = res.json()
        assert body["total"] == 1
        assert body["data"][0]["repo_full_name"] == "u/r2"


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
        with patch("app.depsops.router.run_dependabot_ops", return_value=(0, 0, 0)):
            res = client.post("/admin/dependabot-ops", headers=HEADERS)
        assert res.status_code == 202
        assert "background" in res.json()["message"].lower()
