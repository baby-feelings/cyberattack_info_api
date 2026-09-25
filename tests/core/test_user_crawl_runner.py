"""app.core.user_crawl_runner.run_user_crawls_for_all_accounts（Issue #227）のテスト。"""
from unittest.mock import patch

from app.auth.account_store import set_slack_webhook, upsert_user_token
from app.core.user_crawl_runner import run_user_crawls_for_all_accounts


class TestRunUserCrawlsForAllAccounts:
    def test_skips_accounts_without_webhook(self, db_session, monkeypatch):
        monkeypatch.setattr(
            "app.core.user_crawl_runner.settings.GITHUB_USERNAME", "baby-feelings",
        )
        upsert_user_token(db_session, "no-webhook-user", "token")

        with patch("app.core.user_crawl_runner.run_depscan_for_user") as mock_depscan, \
             patch("app.core.user_crawl_runner.run_codescan_for_user") as mock_codescan, \
             patch("app.core.user_crawl_runner.run_dependabot_ops_for_user") as mock_depsops:
            processed = run_user_crawls_for_all_accounts()

        assert processed == 0
        mock_depscan.assert_not_called()
        mock_codescan.assert_not_called()
        mock_depsops.assert_not_called()

    def test_excludes_github_username_itself(self, db_session, monkeypatch):
        monkeypatch.setattr(
            "app.core.user_crawl_runner.settings.GITHUB_USERNAME", "baby-feelings",
        )
        upsert_user_token(db_session, "baby-feelings", "token")
        set_slack_webhook(db_session, "baby-feelings", "https://hooks.slack.com/services/owner")

        with patch("app.core.user_crawl_runner.run_depscan_for_user") as mock_depscan:
            processed = run_user_crawls_for_all_accounts()

        assert processed == 0
        mock_depscan.assert_not_called()

    def test_runs_all_three_for_each_registered_user_with_webhook(self, db_session, monkeypatch):
        monkeypatch.setattr(
            "app.core.user_crawl_runner.settings.GITHUB_USERNAME", "baby-feelings",
        )
        upsert_user_token(db_session, "alice", "token-alice")
        set_slack_webhook(db_session, "alice", "https://hooks.slack.com/services/alice")

        with patch("app.core.user_crawl_runner.run_depscan_for_user") as mock_depscan, \
             patch("app.core.user_crawl_runner.run_codescan_for_user") as mock_codescan, \
             patch("app.core.user_crawl_runner.run_dependabot_ops_for_user") as mock_depsops, \
             patch("app.core.user_crawl_runner.list_target_repos", return_value=[]) as mock_list, \
             patch("app.core.user_crawl_runner.purge_deleted_repos") as mock_purge:
            processed = run_user_crawls_for_all_accounts()

        assert processed == 1
        mock_depscan.assert_called_once_with("alice", "token-alice")
        mock_codescan.assert_called_once_with("alice", "token-alice")
        mock_depsops.assert_called_once_with(
            "alice", "token-alice", "https://hooks.slack.com/services/alice",
        )
        mock_list.assert_called_once_with("alice", "token-alice")
        mock_purge.assert_called_once_with("alice", "token-alice", set())

    def test_one_user_failure_does_not_stop_others(self, db_session, monkeypatch):
        monkeypatch.setattr(
            "app.core.user_crawl_runner.settings.GITHUB_USERNAME", "baby-feelings",
        )
        for username in ("alice", "bob"):
            upsert_user_token(db_session, username, f"token-{username}")
            set_slack_webhook(db_session, username, f"https://hooks.slack.com/services/{username}")

        with patch(
            "app.core.user_crawl_runner.run_depscan_for_user",
            side_effect=[RuntimeError("boom"), None],
        ), patch("app.core.user_crawl_runner.run_codescan_for_user"), \
           patch("app.core.user_crawl_runner.run_dependabot_ops_for_user"), \
           patch("app.core.user_crawl_runner.list_target_repos", return_value=[]), \
           patch("app.core.user_crawl_runner.purge_deleted_repos"):
            processed = run_user_crawls_for_all_accounts()

        assert processed == 1  # 失敗した1件を除く

    def test_skips_account_when_token_cannot_be_decrypted(self, db_session, monkeypatch):
        monkeypatch.setattr(
            "app.core.user_crawl_runner.settings.GITHUB_USERNAME", "baby-feelings",
        )
        upsert_user_token(db_session, "alice", "token-alice")
        set_slack_webhook(db_session, "alice", "https://hooks.slack.com/services/alice")

        with patch(
            "app.core.user_crawl_runner.decrypt_account_token", return_value=None,
        ), patch("app.core.user_crawl_runner.run_depscan_for_user") as mock_depscan:
            processed = run_user_crawls_for_all_accounts()

        assert processed == 0
        mock_depscan.assert_not_called()
