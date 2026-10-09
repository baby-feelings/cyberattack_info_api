"""app.zapscan（ZAP レポートの解析と GitHub Issue 自動起票）のテスト。"""
import json
import os
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")

from app.zapscan.__main__ import main  # noqa: E402
from app.zapscan.issue_management import file_github_issues, parse_alerts  # noqa: E402


def _alert(name: str, riskcode: int, uris: list[str], cweid: str = "693") -> dict:
    return {
        "name": name,
        "riskcode": str(riskcode),  # ZAP の JSON では文字列で出力される
        "count": str(len(uris)),
        "cweid": cweid,
        "solution": "<p>Set the header.</p>",
        "instances": [{"uri": u} for u in uris],
    }


def _write_report(tmp_path: Path, alerts: list[dict]) -> Path:
    path = tmp_path / "zap-report.json"
    path.write_text(json.dumps({"site": [{"alerts": alerts}]}), encoding="utf-8")
    return path


class TestParseAlerts:
    def test_filters_by_min_risk_and_sorts_high_first(self, tmp_path):
        report = _write_report(tmp_path, [
            _alert("Low one", 1, ["http://api:8000/a"]),
            _alert("Medium one", 2, ["http://api:8000/b"]),
            _alert("High one", 3, ["http://api:8000/c"]),
        ])
        alerts = parse_alerts(report, min_risk=2)
        assert [a["name"] for a in alerts] == ["High one", "Medium one"]

    def test_deduplicates_uris_and_strips_html(self, tmp_path):
        report = _write_report(tmp_path, [
            _alert("X", 2, ["http://api:8000/a", "http://api:8000/a"]),
        ])
        alert = parse_alerts(report, min_risk=2)[0]
        assert alert["uris"] == ["http://api:8000/a"]
        assert "<p>" not in alert["solution"]

    def test_returns_empty_when_no_alerts(self, tmp_path):
        assert parse_alerts(_write_report(tmp_path, []), min_risk=0) == []


class TestFileGithubIssues:
    def _alerts(self) -> list[dict]:
        return [{
            "name": "Missing header", "risk": 2, "count": 7, "cwe_id": "693",
            "solution": "Set the header.", "uris": [f"http://api:8000/{i}" for i in range(7)],
        }]

    def test_does_nothing_without_alerts(self):
        with patch("app.core.issue_filing.find_open_issue") as mock_find:
            file_github_issues([], "owner/repo", token="t")
        mock_find.assert_not_called()

    def test_creates_issue_in_target_repo(self):
        with patch("app.core.issue_filing.find_open_issue", return_value=None), \
             patch("app.core.issue_filing.create_issue") as mock_create:
            file_github_issues(self._alerts(), "owner/repo", token="t")
        args = mock_create.call_args[0]
        assert (args[0], args[1]) == ("owner", "repo")
        assert "ZAP" in args[2]
        assert "Missing header" in args[3]
        assert "ほか2件" in args[3]  # URL は最大5件まで、残りは件数表示

    def test_comments_on_existing_open_issue(self):
        with patch("app.core.issue_filing.find_open_issue", return_value=12), \
             patch("app.core.issue_filing.add_issue_comment") as mock_comment, \
             patch("app.core.issue_filing.create_issue") as mock_create:
            file_github_issues(self._alerts(), "owner/repo", token="t")
        mock_comment.assert_called_once()
        mock_create.assert_not_called()


class TestMain:
    def test_fails_fast_when_report_missing(self, tmp_path):
        assert main([str(tmp_path / "missing.json")]) == 1

    def test_files_issues_for_report(self, tmp_path):
        report = _write_report(tmp_path, [_alert("High one", 3, ["http://api:8000/c"])])
        with patch("app.zapscan.__main__.file_github_issues") as mock_file:
            assert main([str(report), "--repo", "owner/repo", "--min-risk", "3"]) == 0
        alerts, repo = mock_file.call_args[0]
        assert repo == "owner/repo"
        assert [a["name"] for a in alerts] == ["High one"]
