"""app.depsops.user_scan.run_dependabot_ops_for_user（Issue #227）のテスト。"""
from unittest.mock import patch

from app.depsops.models import DependabotPrLog
from app.depsops.user_scan import run_dependabot_ops_for_user

_WEBHOOK = "https://hooks.slack.com/services/octocat"


class TestRunDependabotOpsForUser:
    def test_success_path_merges_and_notifies_only_the_user(self, db_session):
        repos = [{"full_name": "octocat/repo"}]
        prs = [{"number": 1, "title": "Bump x from 1.0.0 to 1.0.1"}]
        with patch("app.depsops.user_scan.list_target_repos", return_value=repos), \
             patch("app.depsops.runner.list_open_dependabot_prs", return_value=prs), \
             patch("app.depsops.runner.has_ci_workflows", return_value=True), \
             patch("app.depsops.runner.list_open_dependabot_alerts", return_value=[]), \
             patch(
                 "app.depsops.runner.get_pull_request",
                 return_value={"mergeable_state": "clean"},
             ), \
             patch("app.depsops.runner.merge_pull_request") as mock_merge, \
             patch("app.depsops.user_scan.notify_dependabot_ops") as mock_notify:
            run_dependabot_ops_for_user("octocat", "gho_token", _WEBHOOK)

        mock_merge.assert_called_once_with("octocat", "repo", 1, "gho_token")
        mock_notify.assert_called_once()
        assert mock_notify.call_args.kwargs["recipients"] == [_WEBHOOK]
        merged_arg = mock_notify.call_args[0][0]
        assert merged_arg[0]["repo_full_name"] == "octocat/repo"

    def test_records_pr_logs(self, db_session):
        repos = [{"full_name": "octocat/repo"}]
        prs = [{"number": 1, "title": "Bump x"}]
        with patch("app.depsops.user_scan.list_target_repos", return_value=repos), \
             patch("app.depsops.runner.list_open_dependabot_prs", return_value=prs), \
             patch("app.depsops.runner.has_ci_workflows", return_value=False), \
             patch("app.depsops.runner.list_open_dependabot_alerts", return_value=[]), \
             patch(
                 "app.depsops.runner.get_pull_request",
                 return_value={"mergeable_state": "clean"},
             ), \
             patch("app.depsops.user_scan.notify_dependabot_ops"):
            run_dependabot_ops_for_user("octocat", "gho_token", _WEBHOOK)

        log = db_session.query(DependabotPrLog).filter_by(repo_full_name="octocat/repo").first()
        assert log is not None
        assert log.action == "flagged"

    def test_no_open_prs_skips_repo_but_still_notifies(self, db_session):
        """PRが無くても（0件でも）notify_dependabot_opsは呼ぶ（baseline実行と同じ
        既定挙動。実際にSlackへ送信するかどうかはnotify_dependabot_ops内部の
        0件ガードが判断する）。"""
        repos = [{"full_name": "octocat/repo"}]
        with patch("app.depsops.user_scan.list_target_repos", return_value=repos), \
             patch("app.depsops.runner.list_open_dependabot_prs", return_value=[]), \
             patch("app.depsops.runner.has_ci_workflows") as mock_has_ci, \
             patch("app.depsops.user_scan.notify_dependabot_ops") as mock_notify:
            run_dependabot_ops_for_user("octocat", "gho_token", _WEBHOOK)
        mock_has_ci.assert_not_called()
        mock_notify.assert_called_once_with([], [], recipients=[_WEBHOOK])

    def test_outer_failure_does_not_raise(self, db_session):
        with patch(
            "app.depsops.user_scan.list_target_repos", side_effect=RuntimeError("API down"),
        ):
            run_dependabot_ops_for_user("octocat", "gho_token", _WEBHOOK)  # 例外を送出しない
