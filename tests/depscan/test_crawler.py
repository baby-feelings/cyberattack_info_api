"""app.depscan.crawler（DEPSCAN ジョブの組み立て）のテスト。"""
import os
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")



TEST_API_KEY = "test-api-key-for-pytest"
HEADERS = {"X-API-KEY": TEST_API_KEY}
_NOW = datetime.now(UTC)
_REPO = "app.core.github.repo.GitHubRepo"

from app.depscan.crawler import fetch_and_scan_dependencies  # noqa: E402


class TestFetchAndScanDependenciesDeduplication:
    """Issue #239: APScheduler・GitHub Actionsの二重トリガー対策。"""

    def test_skips_when_already_succeeded_today(self, db_session):
        from datetime import datetime

        from app.crawler_logs.models import CrawlerLog

        db_session.add(CrawlerLog(
            crawler_type="DEPSCAN", status="success",
            started_at=datetime.now(UTC), finished_at=datetime.now(UTC),
            duration_seconds=1.0,
        ))
        db_session.commit()

        with patch("app.depscan.crawler.collect_dependencies") as mock_collect:
            result = fetch_and_scan_dependencies()

        assert result == (0, 0, 0)
        mock_collect.assert_not_called()

    def test_force_bypasses_the_skip(self, db_session):
        from datetime import datetime

        from app.crawler_logs.models import CrawlerLog

        db_session.add(CrawlerLog(
            crawler_type="DEPSCAN", status="success",
            started_at=datetime.now(UTC), finished_at=datetime.now(UTC),
            duration_seconds=1.0,
        ))
        db_session.commit()

        with patch(
            "app.depscan.crawler.collect_dependencies", return_value=({}, 0, {}),
        ), patch(
            "app.depscan.crawler.build_findings", return_value=[],
        ), patch("app.core.crawler_runner.SessionLocal", return_value=db_session), \
           patch("app.depscan.crawler.apply_reachability"), \
           patch("app.depscan.crawler.notify_dependency_findings"), \
           patch("app.depscan.crawler.file_github_issues"):
            db_session.close = MagicMock()
            new_count, resolved_count, repos_scanned = fetch_and_scan_dependencies(force=True)

        assert repos_scanned == 0


class TestFetchAndScanDependencies:
    def test_success_path(self, db_session):
        with patch(
            "app.depscan.crawler.collect_dependencies",
            return_value=(
                {("PyPI", "pkg", "1.0.0"): [("u/r", "requirements.txt")]}, 1, {"u/r": "public"},
            ),
        ), patch(
            "app.depscan.crawler.build_findings",
            return_value=[{
                "repo_full_name": "u/r", "ecosystem": "PyPI", "package_name": "pkg",
                "installed_version": "1.0.0", "osv_id": "GHSA-001", "severity": "HIGH",
                "cvss_score": 7.5, "summary": "vuln", "fixed_versions": [],
                "manifest_path": "requirements.txt", "detected_at": _NOW,
            }],
        ), patch("app.core.crawler_runner.SessionLocal", return_value=db_session), \
           patch("app.depscan.crawler.apply_reachability") as mock_reachability, \
           patch("app.depscan.crawler.notify_dependency_findings") as mock_notify, \
           patch("app.depscan.crawler.file_github_issues") as mock_file_issues:
            new_count, resolved_count, repos_scanned = fetch_and_scan_dependencies()

        assert new_count == 1
        assert repos_scanned == 1
        mock_reachability.assert_called_once()
        mock_notify.assert_called_once()
        mock_file_issues.assert_called_once()

    def test_delete_failure_does_not_fail_crawler(self, db_session):
        """保持期間超過の削除（delete_old_resolved）が失敗してもクローラー全体はエラーにならないこと。"""
        with patch(
            "app.depscan.crawler.collect_dependencies", return_value=({}, 0, {}),
        ), patch(
            "app.depscan.crawler.build_findings", return_value=[],
        ), patch("app.core.crawler_runner.SessionLocal", return_value=db_session), \
           patch("app.depscan.crawler.apply_reachability"), \
           patch(
               "app.depscan.repository.DependencyFindingRepository.delete_old_resolved",
               side_effect=Exception("delete failed"),
           ), \
           patch("app.depscan.crawler.notify_dependency_findings"), \
           patch("app.depscan.crawler.file_github_issues"):
            new_count, resolved_count, repos_scanned = fetch_and_scan_dependencies()

        assert new_count == 0
        assert repos_scanned == 0

    def test_error_path_logs_and_notifies(self, db_session):
        with patch(
            "app.depscan.crawler.collect_dependencies",
            side_effect=RuntimeError("GitHub API down"),
        ), patch("app.core.crawler_runner.SessionLocal", return_value=db_session), \
           patch("app.core.crawler_runner.notify_error") as mock_notify_error:
            import pytest
            with pytest.raises(RuntimeError):
                fetch_and_scan_dependencies()
        mock_notify_error.assert_called_once()
