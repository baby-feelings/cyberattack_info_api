"""`notify_dependabot_ops`（Slack 通知）のテスト。
"""
import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")


from app.depsops.notifier import notify_dependabot_ops  # noqa: E402

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
# app.core.notifications.notify_dependabot_ops
# ──────────────────────────────────────────────────────────────


class TestNotifyDependabotOps:
    def test_skips_when_no_webhook(self):
        merged = [{"repo_full_name": "u/r", "pr_number": 1, "title": "bump x"}]
        with patch("app.core.notifications.slack.send_slack") as mock_send:
            notify_dependabot_ops(merged, [], recipients=[])
        mock_send.assert_not_called()

    def test_skips_when_both_empty(self):
        with patch("app.core.notifications.slack.send_slack") as mock_send:
            notify_dependabot_ops([], [], recipients=["https://hooks.slack.com/x"])
        mock_send.assert_not_called()

    def test_includes_merged_and_flagged_sections(self):
        merged = [{"repo_full_name": "u/r1", "pr_number": 1, "title": "bump x"}]
        flagged = [
            {"repo_full_name": "u/r2", "pr_number": 2, "title": "bump y", "reason": "メジャー"},
        ]
        with patch("app.core.notifications.slack.send_slack") as mock_send:
            notify_dependabot_ops(merged, flagged, recipients=["https://hooks.slack.com/x"])
        message = mock_send.call_args[0][0]
        assert "u/r1" in message and "自動マージ（1件・1リポジトリ）" in message
        assert "メジャー 1件" in message and "要確認（1件・1リポジトリ）" in message
        # PR のタイトル・番号は載せない（概要のみ）
        assert "bump x" not in message and "bump y" not in message

    def test_summarizes_many_prs_per_repo_and_reason(self):
        merged = [
            {"repo_full_name": "u/r1", "pr_number": n, "title": f"bump {n}"} for n in range(5)
        ] + [{"repo_full_name": "u/r2", "pr_number": 9, "title": "bump z"}]
        flagged = [
            {"repo_full_name": "u/r1", "pr_number": 20, "title": "a", "reason": "メジャー"},
            {"repo_full_name": "u/r2", "pr_number": 21, "title": "b", "reason": "メジャー"},
            {"repo_full_name": "u/r2", "pr_number": 22, "title": "c", "reason": "CI失敗"},
        ]
        with patch("app.core.notifications.slack.send_slack") as mock_send:
            notify_dependabot_ops(merged, flagged, recipients=["https://hooks.slack.com/x"])
        message = mock_send.call_args[0][0]
        assert "自動マージ（6件・2リポジトリ）" in message
        assert "`u/r1` 5件" in message and "`u/r2` 1件" in message
        assert "メジャー 2件" in message and "CI失敗 1件" in message
        assert "要確認（3件・2リポジトリ）" in message
