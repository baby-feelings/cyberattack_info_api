"""app.codescan.crawler（CODESCAN の走査の組み立て）のテスト。"""
import os
from datetime import UTC, datetime

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")

import subprocess
from unittest.mock import patch

from app.codescan.crawler import (  # noqa: E402
    _run_codescan_body,
    fetch_and_scan_code,
    scan_repo,
)
from app.codescan.models import CodeFinding  # noqa: E402
from app.core.crawler_runner import CrawlCounters  # noqa: E402
from tests.codescan.support import (  # noqa: E402
    SAMPLE_GITLEAKS_JSON,
    SAMPLE_SEMGREP_JSON,
    make_tarball,
)

_NOW = datetime.now(UTC)

_REPO = "app.core.github.repo.GitHubRepo"


class TestScanRepo:
    def test_downloads_extracts_runs_semgrep_and_gitleaks_and_parses(self):
        tarball = make_tarball({"app/main.py": "x = 1"}, top_dir="owner-repo-sha")
        with patch(f"{_REPO}.tarball", return_value=tarball), \
             patch("app.codescan.scanners.SemgrepScanner.run", return_value=SAMPLE_SEMGREP_JSON), \
             patch("app.codescan.scanners.GitleaksScanner.run", return_value=SAMPLE_GITLEAKS_JSON):
            records = scan_repo("owner/repo", "main", "token")
        assert len(records) == 2
        tools = {r["tool"] for r in records}
        assert tools == {"semgrep", "gitleaks"}
        assert all(r["repo_full_name"] == "owner/repo" for r in records)

    def test_gitleaks_failure_does_not_lose_semgrep_results(self):
        tarball = make_tarball({"app/main.py": "x = 1"}, top_dir="owner-repo-sha")
        with patch(f"{_REPO}.tarball", return_value=tarball), \
             patch("app.codescan.scanners.SemgrepScanner.run", return_value=SAMPLE_SEMGREP_JSON), \
             patch(
                 "app.codescan.scanners.GitleaksScanner.run",
                 side_effect=subprocess.TimeoutExpired(cmd="gitleaks", timeout=120),
             ):
            records = scan_repo("owner/repo", "main", "token")
        assert len(records) == 1
        assert records[0]["tool"] == "semgrep"

    def test_semgrep_failure_does_not_lose_gitleaks_results(self):
        tarball = make_tarball({"app/main.py": "x = 1"}, top_dir="owner-repo-sha")
        with patch(f"{_REPO}.tarball", return_value=tarball), \
             patch(
                 "app.codescan.scanners.SemgrepScanner.run",
                 side_effect=subprocess.TimeoutExpired(cmd="semgrep", timeout=300),
             ), \
             patch("app.codescan.scanners.GitleaksScanner.run", return_value=SAMPLE_GITLEAKS_JSON):
            records = scan_repo("owner/repo", "main", "token")
        assert len(records) == 1
        assert records[0]["tool"] == "gitleaks"


class TestRunCodescanBody:
    def test_one_repo_failure_does_not_stop_others(self, db_session):
        repos = [
            {"full_name": "owner/repo-fail", "default_branch": "main"},
            {"full_name": "owner/repo-ok", "default_branch": "main"},
        ]

        def _scan_side_effect(full_name, branch, token):
            if full_name == "owner/repo-fail":
                raise subprocess.TimeoutExpired(cmd="semgrep", timeout=300)
            return [{
                "repo_full_name": full_name, "file_path": "a.py", "line_start": 1,
                "line_end": 1, "rule_id": "rule.x", "message": "m", "severity": "ERROR",
                "cwe_ids": [], "owasp_categories": [], "code_snippet": "x",
                "cvss_score": 5.0, "cvss_vector": "v", "detected_at": _NOW,
            }]

        counters = CrawlCounters()
        with patch("app.codescan.crawler.list_target_repos", return_value=repos), \
             patch("app.codescan.crawler.scan_repo", side_effect=_scan_side_effect), \
             patch("app.codescan.crawler.file_github_issues") as mock_issues:
            _run_codescan_body(db_session, counters)

        assert counters.inserted == 1
        ok_count = db_session.query(CodeFinding).filter_by(repo_full_name="owner/repo-ok").count()
        fail_count = db_session.query(CodeFinding).filter_by(
            repo_full_name="owner/repo-fail",
        ).count()
        assert ok_count == 1
        assert fail_count == 0
        mock_issues.assert_called_once()

    def test_issue_filing_failure_does_not_raise(self, db_session):
        repos = [{"full_name": "owner/repo", "default_branch": "main"}]
        counters = CrawlCounters()
        with patch("app.codescan.crawler.list_target_repos", return_value=repos), \
             patch("app.codescan.crawler.scan_repo", return_value=[]), \
             patch("app.codescan.crawler.file_github_issues", side_effect=RuntimeError("boom")):
            _run_codescan_body(db_session, counters)  # 例外を送出しないことを確認


class TestFetchAndScanCode:
    def test_returns_counters_tuple(self, db_session):
        with patch("app.codescan.crawler.run_crawler", return_value=(1, 2, 3)) as mock_run:
            result = fetch_and_scan_code()
        assert result == (1, 2, 3)
        assert mock_run.call_args[0][0] == "CODESCAN"
