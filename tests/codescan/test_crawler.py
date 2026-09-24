"""app.codescan.crawler（CODESCAN 本体処理）のテスト。

tarball 取得・Semgrep 実行の両方をモックし、実際の Semgrep バイナリや GitHub API
通信には依存しない（Windows 開発環境に Semgrep が未インストールでも実行できる）。
"""
import io
import os
import subprocess
import tarfile
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")

from app.codescan.crawler import (  # noqa: E402
    _delete_old_codescan_records,
    _extract_tarball,
    _parse_gitleaks_results,
    _parse_semgrep_results,
    _resolve_stale_repo_findings,
    _run_codescan_body,
    _run_gitleaks,
    _run_semgrep,
    _scan_repo,
    _upsert_repo_findings,
    fetch_and_scan_code,
)
from app.codescan.models import CodeFinding  # noqa: E402
from app.core.crawler_runner import CrawlCounters  # noqa: E402

_NOW = datetime.now(timezone.utc)
_RULE_ID = "python.lang.security.audit.hardcoded-password"

_SAMPLE_SEMGREP_JSON = {
    "results": [
        {
            "check_id": "python.lang.security.audit.hardcoded-password",
            "path": "REPO_ROOT/app/main.py",
            "start": {"line": 10},
            "end": {"line": 10},
            "extra": {
                "message": "Hardcoded password detected",
                "severity": "ERROR",
                "lines": 'PASSWORD = "hunter2"',
                "metadata": {
                    "cwe": ["CWE-798: Use of Hard-coded Credentials"],
                    "owasp": ["A07:2021 - Identification and Authentication Failures"],
                },
            },
        },
    ],
}

# gitleaks のJSON出力サンプル。"Secret"フィールドに実際のシークレット値が
# 平文で含まれることに注意（_parse_gitleaks_resultsがこれを一切保存しないことを
# TestParseGitleaksResultsで検証する）
_SAMPLE_GITLEAKS_JSON = [
    {
        "Description": "AWS Access Key",
        "StartLine": 5,
        "EndLine": 5,
        "RuleID": "aws-access-token",
        "File": "app/config.py",
        "Secret": "AKIAABCDEFGHIJKLMNOP",  # pragma: allowlist secret
        "Match": 'AWS_KEY = "AKIAABCDEFGHIJKLMNOP"',
    },
]


def _make_finding(db_session, **kwargs) -> CodeFinding:
    defaults = {
        "repo_full_name": "baby-feelings/baby_grow",
        "file_path": "app/main.py",
        "line_start": 10,
        "line_end": 10,
        "rule_id": "python.lang.security.audit.hardcoded-password",
        "message": "Hardcoded password detected",
        "severity": "ERROR",
        "cwe_ids": ["CWE-798"],
        "owasp_categories": [],
        "code_snippet": 'PASSWORD = "hunter2"',
        "cvss_score": 7.4,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "detected_at": _NOW,
        "resolved_at": None,
    }
    defaults.update(kwargs)
    record = CodeFinding(**defaults)
    db_session.add(record)
    db_session.commit()
    return record


def _make_tarball(files: dict[str, str], top_dir: str = "owner-repo-abcdef") -> bytes:
    """{相対パス: 内容} からGitHub tarball相当の.tar.gzバイト列を生成する。"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel_path, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=f"{top_dir}/{rel_path}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class TestExtractTarball:
    def test_extracts_and_returns_single_top_level_dir(self, tmp_path):
        tarball = _make_tarball({"app/main.py": "print('hi')"}, top_dir="owner-repo-abc")
        dest = tmp_path / "extract"
        dest.mkdir()

        repo_root = _extract_tarball(tarball, str(dest))

        assert os.path.basename(repo_root) == "owner-repo-abc"
        assert os.path.isfile(os.path.join(repo_root, "app", "main.py"))

    def test_returns_dest_dir_when_no_subdirectory(self, tmp_path):
        # トップレベルディレクトリを持たない（想定外だが安全に動作することを確認）tarball
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            data = b"content"
            info = tarfile.TarInfo(name="flat.txt")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        dest = tmp_path / "extract2"
        dest.mkdir()

        repo_root = _extract_tarball(buf.getvalue(), str(dest))

        assert repo_root == str(dest)


class TestRunSemgrep:
    def test_parses_json_stdout(self):
        fake_result = subprocess.CompletedProcess(
            args=[], returncode=1, stdout='{"results": []}', stderr="",
        )
        with patch("subprocess.run", return_value=fake_result) as mock_run:
            output = _run_semgrep("/some/dir")
        assert output == {"results": []}
        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["timeout"] == 300

    def test_empty_stdout_returns_empty_dict(self):
        fake_result = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("subprocess.run", return_value=fake_result):
            output = _run_semgrep("/some/dir")
        assert output == {}


class TestParseSemgrepResults:
    def test_extracts_fields_and_estimates_cvss(self):
        records = _parse_semgrep_results(
            "baby-feelings/baby_grow", _SAMPLE_SEMGREP_JSON, "REPO_ROOT",
        )
        assert len(records) == 1
        rec = records[0]
        assert rec["repo_full_name"] == "baby-feelings/baby_grow"
        assert rec["file_path"] == "app/main.py"
        assert rec["line_start"] == 10
        assert rec["rule_id"] == "python.lang.security.audit.hardcoded-password"
        assert rec["severity"] == "ERROR"
        assert rec["cwe_ids"] == ["CWE-798: Use of Hard-coded Credentials"]
        assert rec["cvss_score"] is not None
        assert 0.0 <= rec["cvss_score"] <= 10.0
        assert rec["cvss_vector"] is not None

    def test_no_results_returns_empty_list(self):
        records = _parse_semgrep_results("owner/repo", {"results": []}, "/root")
        assert records == []

    def test_missing_metadata_defaults_to_empty_lists(self):
        semgrep_json = {
            "results": [{
                "check_id": "rule.x",
                "path": "/root/a.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"message": "msg", "severity": "INFO", "lines": "x"},
            }],
        }
        records = _parse_semgrep_results("owner/repo", semgrep_json, "/root")
        assert records[0]["cwe_ids"] == []
        assert records[0]["owasp_categories"] == []

    def test_snippet_is_truncated(self):
        long_line = "x" * 5000
        semgrep_json = {
            "results": [{
                "check_id": "rule.x",
                "path": "/root/a.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"message": "msg", "severity": "WARNING", "lines": long_line},
            }],
        }
        records = _parse_semgrep_results("owner/repo", semgrep_json, "/root")
        assert len(records[0]["code_snippet"]) <= 2000


class TestRunGitleaks:
    def test_parses_report_file(self, tmp_path):
        fake_result = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        def _fake_run(cmd, **kwargs):
            # gitleaksは --report-path に指定されたファイルへJSONを書き出す
            report_path = cmd[cmd.index("--report-path") + 1]
            with open(report_path, "w", encoding="utf-8") as f:
                f.write('[{"RuleID": "aws-access-token"}]')
            return fake_result

        with patch("subprocess.run", side_effect=_fake_run) as mock_run:
            output = _run_gitleaks(str(tmp_path))
        assert output == [{"RuleID": "aws-access-token"}]
        call_args = mock_run.call_args
        assert call_args.args[0][0] == "gitleaks"
        assert "--no-git" in call_args.args[0]
        assert "--exit-code" in call_args.args[0]
        assert call_args.kwargs["timeout"] == 120

    def test_empty_report_returns_empty_list(self, tmp_path):
        fake_result = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        def _fake_run(cmd, **kwargs):
            report_path = cmd[cmd.index("--report-path") + 1]
            with open(report_path, "w", encoding="utf-8"):
                pass  # 空ファイル（検知0件）
            return fake_result

        with patch("subprocess.run", side_effect=_fake_run):
            output = _run_gitleaks(str(tmp_path))
        assert output == []

    def test_report_file_is_removed_after_run(self, tmp_path):
        captured_path = {}

        def _fake_run(cmd, **kwargs):
            report_path = cmd[cmd.index("--report-path") + 1]
            captured_path["path"] = report_path
            with open(report_path, "w", encoding="utf-8") as f:
                f.write("[]")
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=_fake_run):
            _run_gitleaks(str(tmp_path))
        assert not os.path.exists(captured_path["path"])


class TestParseGitleaksResults:
    def test_extracts_fields_without_leaking_secret_value(self):
        records = _parse_gitleaks_results("owner/repo", _SAMPLE_GITLEAKS_JSON)
        assert len(records) == 1
        rec = records[0]
        assert rec["repo_full_name"] == "owner/repo"
        assert rec["file_path"] == "app/config.py"
        assert rec["line_start"] == 5
        assert rec["line_end"] == 5
        assert rec["rule_id"] == "gitleaks:aws-access-token"
        assert rec["message"] == "AWS Access Key"
        assert rec["severity"] == "ERROR"
        assert rec["cwe_ids"] == ["CWE-798"]
        assert rec["tool"] == "gitleaks"
        assert rec["cvss_score"] is not None
        assert rec["cvss_vector"] is not None
        # 【重要】実際のシークレット値（Secret/Match）が一切保存されていないことを確認
        assert "AKIAABCDEFGHIJKLMNOP" not in rec["code_snippet"]
        assert "AKIAABCDEFGHIJKLMNOP" not in str(rec.values())
        assert "検知内容: AWS Access Key" == rec["code_snippet"]

    def test_no_results_returns_empty_list(self):
        assert _parse_gitleaks_results("owner/repo", []) == []

    def test_missing_description_falls_back_to_generic_message(self):
        records = _parse_gitleaks_results(
            "owner/repo",
            [{"RuleID": "generic-api-key", "File": "a.py", "StartLine": 1, "EndLine": 1}],
        )
        assert records[0]["message"] == "Secret detected"


class TestScanRepo:
    def test_downloads_extracts_runs_semgrep_and_gitleaks_and_parses(self):
        tarball = _make_tarball({"app/main.py": "x = 1"}, top_dir="owner-repo-sha")
        with patch("app.codescan.crawler.download_repo_tarball", return_value=tarball), \
             patch("app.codescan.crawler._run_semgrep", return_value=_SAMPLE_SEMGREP_JSON), \
             patch("app.codescan.crawler._run_gitleaks", return_value=_SAMPLE_GITLEAKS_JSON):
            records = _scan_repo("owner/repo", "main", "token")
        assert len(records) == 2
        tools = {r["tool"] for r in records}
        assert tools == {"semgrep", "gitleaks"}
        assert all(r["repo_full_name"] == "owner/repo" for r in records)

    def test_gitleaks_failure_does_not_lose_semgrep_results(self):
        tarball = _make_tarball({"app/main.py": "x = 1"}, top_dir="owner-repo-sha")
        with patch("app.codescan.crawler.download_repo_tarball", return_value=tarball), \
             patch("app.codescan.crawler._run_semgrep", return_value=_SAMPLE_SEMGREP_JSON), \
             patch(
                 "app.codescan.crawler._run_gitleaks",
                 side_effect=subprocess.TimeoutExpired(cmd="gitleaks", timeout=120),
             ):
            records = _scan_repo("owner/repo", "main", "token")
        assert len(records) == 1
        assert records[0]["tool"] == "semgrep"

    def test_semgrep_failure_does_not_lose_gitleaks_results(self):
        tarball = _make_tarball({"app/main.py": "x = 1"}, top_dir="owner-repo-sha")
        with patch("app.codescan.crawler.download_repo_tarball", return_value=tarball), \
             patch(
                 "app.codescan.crawler._run_semgrep",
                 side_effect=subprocess.TimeoutExpired(cmd="semgrep", timeout=300),
             ), \
             patch("app.codescan.crawler._run_gitleaks", return_value=_SAMPLE_GITLEAKS_JSON):
            records = _scan_repo("owner/repo", "main", "token")
        assert len(records) == 1
        assert records[0]["tool"] == "gitleaks"


class TestUpsertRepoFindings:
    def test_inserts_new_finding(self, db_session):
        rec = {
            "repo_full_name": "owner/repo", "file_path": "a.py", "line_start": 1,
            "line_end": 1, "rule_id": "rule.x", "message": "m", "severity": "ERROR",
            "cwe_ids": [], "owasp_categories": [], "code_snippet": "x",
            "cvss_score": 5.0, "cvss_vector": "v", "detected_at": _NOW,
            "resolved_at": None,
        }
        inserted, snapshots = _upsert_repo_findings(db_session, "owner/repo", [rec])
        assert inserted == 1
        assert len(snapshots) == 1
        assert db_session.query(CodeFinding).count() == 1

    def test_duplicate_keys_in_same_batch_counted_once(self, db_session):
        rec = {
            "repo_full_name": "owner/repo", "file_path": "a.py", "line_start": 1,
            "line_end": 1, "rule_id": "rule.x", "message": "m", "severity": "ERROR",
            "cwe_ids": [], "owasp_categories": [], "code_snippet": "x",
            "cvss_score": 5.0, "cvss_vector": "v", "detected_at": _NOW,
            "resolved_at": None,
        }
        inserted, _ = _upsert_repo_findings(db_session, "owner/repo", [rec, dict(rec)])
        assert inserted == 1

    def test_existing_unresolved_finding_is_updated_not_duplicated(self, db_session):
        _make_finding(db_session, message="old message", severity="WARNING")
        rec = {
            "repo_full_name": "baby-feelings/baby_grow", "file_path": "app/main.py",
            "line_start": 10, "line_end": 10, "rule_id": _RULE_ID,
            "message": "new message", "severity": "ERROR", "cwe_ids": ["CWE-798"],
            "owasp_categories": [], "code_snippet": "x", "cvss_score": 9.0,
            "cvss_vector": "v2", "detected_at": _NOW, "resolved_at": None,
        }
        inserted, snapshots = _upsert_repo_findings(db_session, "baby-feelings/baby_grow", [rec])
        assert inserted == 0
        assert snapshots == []
        assert db_session.query(CodeFinding).count() == 1
        updated = db_session.query(CodeFinding).first()
        assert updated.message == "new message"
        assert updated.severity == "ERROR"

    def test_reoccurrence_of_resolved_finding_reopens_it(self, db_session):
        _make_finding(db_session, resolved_at=_NOW)
        rec = {
            "repo_full_name": "baby-feelings/baby_grow", "file_path": "app/main.py",
            "line_start": 10, "line_end": 10, "rule_id": _RULE_ID,
            "message": "m", "severity": "ERROR", "cwe_ids": [], "owasp_categories": [],
            "code_snippet": "x", "cvss_score": 5.0, "cvss_vector": "v",
            "detected_at": _NOW, "resolved_at": None,
        }
        inserted, snapshots = _upsert_repo_findings(db_session, "baby-feelings/baby_grow", [rec])
        assert inserted == 0  # 再発は新規カウントしない
        updated = db_session.query(CodeFinding).first()
        assert updated.resolved_at is None


class TestResolveStaleRepoFindings:
    def test_marks_unmatched_findings_as_resolved(self, db_session):
        _make_finding(db_session)
        resolved = _resolve_stale_repo_findings(db_session, "baby-feelings/baby_grow", set())
        assert resolved == 1
        updated = db_session.query(CodeFinding).first()
        assert updated.resolved_at is not None

    def test_keeps_matching_findings_unresolved(self, db_session):
        _make_finding(db_session)
        key = ("baby-feelings/baby_grow", "app/main.py", _RULE_ID, 10)
        resolved = _resolve_stale_repo_findings(db_session, "baby-feelings/baby_grow", {key})
        assert resolved == 0
        updated = db_session.query(CodeFinding).first()
        assert updated.resolved_at is None

    def test_only_affects_specified_repo(self, db_session):
        _make_finding(db_session, repo_full_name="other/repo")
        resolved = _resolve_stale_repo_findings(db_session, "baby-feelings/baby_grow", set())
        assert resolved == 0


class TestDeleteOldCodescanRecords:
    def test_deletes_old_resolved_records(self, db_session):
        old_date = _NOW - timedelta(days=200)
        _make_finding(db_session, resolved_at=old_date)
        deleted = _delete_old_codescan_records(db_session)
        assert deleted == 1
        assert db_session.query(CodeFinding).count() == 0

    def test_does_not_delete_unresolved_records(self, db_session):
        _make_finding(db_session, resolved_at=None)
        deleted = _delete_old_codescan_records(db_session)
        assert deleted == 0
        assert db_session.query(CodeFinding).count() == 1

    def test_does_not_delete_recently_resolved_records(self, db_session):
        _make_finding(db_session, resolved_at=_NOW - timedelta(days=1))
        deleted = _delete_old_codescan_records(db_session)
        assert deleted == 0


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
             patch("app.codescan.crawler._scan_repo", side_effect=_scan_side_effect), \
             patch("app.codescan.crawler._file_github_issues") as mock_issues:
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
             patch("app.codescan.crawler._scan_repo", return_value=[]), \
             patch("app.codescan.crawler._file_github_issues", side_effect=RuntimeError("boom")):
            _run_codescan_body(db_session, counters)  # 例外を送出しないことを確認


class TestFetchAndScanCode:
    def test_returns_counters_tuple(self, db_session):
        with patch("app.codescan.crawler.run_crawler", return_value=(1, 2, 3)) as mock_run:
            result = fetch_and_scan_code()
        assert result == (1, 2, 3)
        assert mock_run.call_args[0][0] == "CODESCAN"
