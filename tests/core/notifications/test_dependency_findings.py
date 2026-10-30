"""app.core.notifications.dependency_findings（DEPSCAN 検知の Slack 通知）のテスト。"""
import os
from datetime import UTC, datetime
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")



TEST_API_KEY = "test-api-key-for-pytest"
HEADERS = {"X-API-KEY": TEST_API_KEY}
_NOW = datetime.now(UTC)
_REPO = "app.core.github.repo.GitHubRepo"

from app.core.notifications.dependency_findings import notify_dependency_findings  # noqa: E402


class TestNotifyDependencyFindings:
    def _finding_dict(self, **kwargs):
        base = {
            "repo_full_name": "baby-feelings/baby_grow",
            "package_name": "cryptography",
            "installed_version": "3.4.7",
            "severity": "HIGH",
            "fixed_versions": ["3.4.8"],
            "osv_id": "GHSA-001",
        }
        base.update(kwargs)
        return base

    def test_skips_when_no_webhook(self):
        with patch("app.core.notifications.slack.send_slack") as mock_send:
            notify_dependency_findings([self._finding_dict()], recipients=[])
        mock_send.assert_not_called()

    def test_skips_when_empty(self):
        with patch("app.core.notifications.slack.send_slack") as mock_send:
            notify_dependency_findings([], recipients=["https://hooks.slack.com/x"])
        mock_send.assert_not_called()

    def test_sends_digest_grouped_by_repo(self):
        findings = [
            self._finding_dict(repo_full_name="u/a", osv_id="GHSA-a"),
            self._finding_dict(repo_full_name="u/b", osv_id="GHSA-b"),
        ]
        with patch("app.core.notifications.slack.send_slack") as mock_send:
            notify_dependency_findings(findings, recipients=["https://hooks.slack.com/x"])
        mock_send.assert_called_once()
        message = mock_send.call_args[0][0]
        assert "u/a" in message
        assert "u/b" in message
        assert "cryptography" in message

    def test_consolidates_same_package_into_one_line(self):
        """同一パッケージ×バージョンの複数CVEは1行に集約され、件数・重大度内訳を表示する。"""
        findings = [
            self._finding_dict(osv_id="GHSA-a", severity="HIGH", fixed_versions=["3.4.8"]),
            self._finding_dict(osv_id="GHSA-b", severity="CRITICAL", fixed_versions=["3.5.0"]),
            self._finding_dict(osv_id="GHSA-c", severity="HIGH", fixed_versions=["3.4.8"]),
        ]
        with patch("app.core.notifications.slack.send_slack") as mock_send:
            notify_dependency_findings(findings, recipients=["https://hooks.slack.com/x"])
        message = mock_send.call_args[0][0]
        # 3件のCVEが1行（1パッケージ）に集約されている
        assert message.count("cryptography 3.4.7") == 1
        assert "CRITICAL×1" in message
        assert "HIGH×2" in message
        assert "計3件" in message
        assert "3.4.8" in message and "3.5.0" in message

    def test_sorts_packages_by_severity_within_repo(self):
        """リポジトリ内はCRITICAL→HIGH→...の重大度順に並ぶ。"""
        findings = [
            self._finding_dict(package_name="low-pkg", severity="LOW", osv_id="GHSA-l"),
            self._finding_dict(package_name="critical-pkg", severity="CRITICAL", osv_id="GHSA-c"),
            self._finding_dict(package_name="high-pkg", severity="HIGH", osv_id="GHSA-h"),
        ]
        with patch("app.core.notifications.slack.send_slack") as mock_send:
            notify_dependency_findings(findings, recipients=["https://hooks.slack.com/x"])
        message = mock_send.call_args[0][0]
        assert (
            message.index("critical-pkg")
            < message.index("high-pkg")
            < message.index("low-pkg")
        )

    def test_no_repo_limit(self):
        """対象リポジトリ数が多くても省略せず全リポジトリを表示する。"""
        findings = [
            self._finding_dict(repo_full_name=f"u/repo{i}", osv_id=f"GHSA-{i}")
            for i in range(20)
        ]
        with patch("app.core.notifications.slack.send_slack") as mock_send:
            notify_dependency_findings(findings, recipients=["https://hooks.slack.com/x"])
        message = mock_send.call_args[0][0]
        for i in range(20):
            assert f"u/repo{i}" in message
        assert "他" not in message

    def test_truncates_overly_long_message(self):
        """Slack の文字数上限を超える場合、行の途中で切らずに省略する。"""
        findings = [
            self._finding_dict(
                repo_full_name=f"u/repo{i}", package_name=f"pkg-{i}", osv_id=f"GHSA-{i}",
            )
            for i in range(2000)
        ]
        with patch("app.core.notifications.slack.send_slack") as mock_send:
            notify_dependency_findings(findings, recipients=["https://hooks.slack.com/x"])
        message = mock_send.call_args[0][0]
        assert len(message) <= 39000 + 100
        assert message.endswith(
            "（メッセージが長すぎるため以降省略。詳細は API / ダッシュボードを参照）"
        )
        assert not message.endswith("\n")


class TestMaliciousPackageNotification:
    def _finding(self, **kwargs):
        base = {
            "repo_full_name": "u/a",
            "package_name": "evil-pkg",
            "installed_version": "1.0.0",
            "severity": "CRITICAL",
            "fixed_versions": [],
            "osv_id": "MAL-2026-1",
        }
        base.update(kwargs)
        return base

    def test_sends_separate_urgent_message_with_steps_before_the_digest(self):
        findings = [
            self._finding(package_name="cryptography", osv_id="GHSA-1", severity="HIGH"),
            self._finding(),
        ]
        with patch("app.core.notifications.slack.send_slack") as mock_send:
            notify_dependency_findings(findings, recipients=["https://hooks.slack.com/x"])

        assert mock_send.call_count == 2
        urgent, digest = (c[0][0] for c in mock_send.call_args_list)
        assert "【緊急】悪意あるパッケージ" in urgent
        assert "対応手順" in urgent
        assert "evil-pkg" in urgent
        # ダイジェストには、悪意あるパッケージを混ぜない（二重に通知しない）
        assert "evil-pkg" not in digest
        assert "cryptography" in digest
        assert "1件検知" in digest

    def test_only_malicious_sends_only_the_urgent_message(self):
        with patch("app.core.notifications.slack.send_slack") as mock_send:
            notify_dependency_findings([self._finding()], recipients=["https://hooks.slack.com/x"])

        mock_send.assert_called_once()
        assert "【緊急】" in mock_send.call_args[0][0]

    def test_no_urgent_message_without_malicious(self):
        with patch("app.core.notifications.slack.send_slack") as mock_send:
            notify_dependency_findings(
                [self._finding(osv_id="GHSA-1", severity="HIGH")],
                recipients=["https://hooks.slack.com/x"],
            )

        mock_send.assert_called_once()
        assert "【緊急】" not in mock_send.call_args[0][0]
