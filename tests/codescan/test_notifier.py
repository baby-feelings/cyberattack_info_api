"""CODESCAN の新規検知の Slack 通知（リポジトリ別の概要）のテスト。"""
from unittest.mock import patch

from app.codescan.notifier import notify_code_findings

_URL = "https://hooks.slack.com/x"


def _f(repo, severity, tool):
    return {"repo_full_name": repo, "severity": severity, "tool": tool, "rule_id": "r"}


class TestNotifyCodeFindings:
    def test_skips_when_no_findings(self):
        with patch("app.core.notifications.slack.send_slack") as mock_send:
            notify_code_findings([], recipients=[_URL])
        mock_send.assert_not_called()

    def test_skips_when_no_webhook(self):
        with patch("app.core.notifications.slack.send_slack") as mock_send:
            notify_code_findings([_f("u/r", "ERROR", "semgrep")], recipients=[])
        mock_send.assert_not_called()

    def test_groups_by_repo_with_severity_and_tool_counts(self):
        findings = [
            _f("u/b", "WARNING", "zizmor"),
            _f("u/a", "ERROR", "semgrep"),
            _f("u/a", "ERROR", "gitleaks"),
            _f("u/a", "INFO", "zizmor"),
        ]
        with patch("app.core.notifications.slack.send_slack") as mock_send:
            notify_code_findings(findings, recipients=[_URL])
        message = mock_send.call_args[0][0]
        assert "4件検知（2リポジトリ）" in message
        # リポジトリ名の昇順で、重い順に重要度を並べる
        assert message.index("*u/a*（3件）") < message.index("*u/b*（1件）")
        assert "重要度: ERROR 2・INFO 1" in message
        assert "ツール: Gitleaks 1・Semgrep 1・Zizmor 1" in message
        assert "重要度: WARNING 1" in message and "ツール: Zizmor 1" in message
        assert "ダッシュボード" in message

    def test_unknown_tool_and_severity_do_not_break(self):
        with patch("app.core.notifications.slack.send_slack") as mock_send:
            notify_code_findings([{"repo_full_name": "u/r"}], recipients=[_URL])
        message = mock_send.call_args[0][0]
        assert "重要度: 不明 1" in message and "ツール: 不明 1" in message
