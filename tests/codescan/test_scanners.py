"""app.codescan.scanners（Semgrep / gitleaks の実行とレコード化）のテスト。"""
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")

import subprocess
from unittest.mock import patch

import pytest

from app.codescan.scanners import (  # noqa: E402
    GitleaksScanner,
    Scanner,
    SemgrepScanner,
    default_scanners,
)
from tests.codescan.support import (  # noqa: E402
    SAMPLE_GITLEAKS_JSON,
    SAMPLE_SEMGREP_JSON,
)


class TestRunSemgrep:
    def test_parses_json_stdout(self):
        fake_result = subprocess.CompletedProcess(
            args=[], returncode=1, stdout='{"results": []}', stderr="",
        )
        with patch("subprocess.run", return_value=fake_result) as mock_run:
            output = SemgrepScanner().run("/some/dir")
        assert output == {"results": []}
        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs["timeout"] == 300

    def test_empty_stdout_returns_empty_dict(self):
        fake_result = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with patch("subprocess.run", return_value=fake_result):
            output = SemgrepScanner().run("/some/dir")
        assert output == {}


class TestParseSemgrepResults:
    def test_extracts_fields_and_estimates_cvss(self):
        records = SemgrepScanner().parse(
            "baby-feelings/baby_grow", SAMPLE_SEMGREP_JSON, "REPO_ROOT",
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
        records = SemgrepScanner().parse("owner/repo", {"results": []}, "/root")
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
        records = SemgrepScanner().parse("owner/repo", semgrep_json, "/root")
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
        records = SemgrepScanner().parse("owner/repo", semgrep_json, "/root")
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
            output = GitleaksScanner().run(str(tmp_path))
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
            output = GitleaksScanner().run(str(tmp_path))
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
            GitleaksScanner().run(str(tmp_path))
        assert not os.path.exists(captured_path["path"])

    def test_omits_config_flag_when_repo_has_no_gitleaks_toml(self, tmp_path):
        """対象リポジトリに.gitleaks.tomlが無い場合は--configを付与しない（デフォルトルールで検知）。"""
        fake_result = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        def _fake_run(cmd, **kwargs):
            report_path = cmd[cmd.index("--report-path") + 1]
            with open(report_path, "w", encoding="utf-8") as f:
                f.write("[]")
            return fake_result

        with patch("subprocess.run", side_effect=_fake_run) as mock_run:
            GitleaksScanner().run(str(tmp_path))
        assert "--config" not in mock_run.call_args.args[0]

    def test_uses_repo_gitleaks_toml_when_present(self, tmp_path):
        """対象リポジトリのルートに.gitleaks.tomlがあれば--configで明示的に渡す（Issue #221）。

        gitleaksは--source配下の設定ファイルを自動探索しないため、各リポジトリが
        自身のallowlist（テストフィクスチャのダミーシークレット等の既知の誤検知除外）を
        持てるようにするには、呼び出し側で明示的に検出して渡す必要がある。
        """
        config_path = tmp_path / ".gitleaks.toml"
        config_path.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
        fake_result = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        def _fake_run(cmd, **kwargs):
            report_path = cmd[cmd.index("--report-path") + 1]
            with open(report_path, "w", encoding="utf-8") as f:
                f.write("[]")
            return fake_result

        with patch("subprocess.run", side_effect=_fake_run) as mock_run:
            GitleaksScanner().run(str(tmp_path))
        cmd = mock_run.call_args.args[0]
        assert "--config" in cmd
        assert cmd[cmd.index("--config") + 1] == str(config_path)


class TestParseGitleaksResults:
    def test_extracts_fields_without_leaking_secret_value(self):
        records = GitleaksScanner().parse("owner/repo", SAMPLE_GITLEAKS_JSON, "/tmp/repo_root")
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
        assert GitleaksScanner().parse("owner/repo", [], "/tmp/repo_root") == []

    def test_missing_description_falls_back_to_generic_message(self):
        records = GitleaksScanner().parse(
            "owner/repo",
            [{"RuleID": "generic-api-key", "File": "a.py", "StartLine": 1, "EndLine": 1}],
            "/tmp/repo_root",
        )
        assert records[0]["message"] == "Secret detected"

    # 本番・CI は Linux。Windows では "/tmp/..." がドライブ文字なしで絶対パスとみなされず、
    # 検証できないためスキップする
    @pytest.mark.skipif(os.name == "nt", reason="POSIX の絶対パス（/tmp/...）を前提にしたテスト")
    def test_normalizes_absolute_file_path_to_repo_relative(self):
        """gitleaksが--sourceディレクトリ基準の絶対パスを返す実運用のケースを再現する。

        本番の初回実行で実際に発生した不具合の回帰テスト: file_pathに
        tempfile.TemporaryDirectory()が生成するランダムな一時ディレクトリ名が
        残っていると、毎回のスキャンでUpsertの自然キーが変わってしまい
        重複検知が際限なく蓄積する。
        """
        repo_root = "/tmp/tmpabcdef/owner-repo-somehash"
        records = GitleaksScanner().parse(
            "owner/repo",
            [{
                "RuleID": "gcp-api-key", "File": f"{repo_root}/lib/config.dart",
                "StartLine": 3, "EndLine": 3, "Description": "GCP API key",
            }],
            repo_root,
        )
        assert records[0]["file_path"] == "lib/config.dart"


class TestScannerStrategy:
    def test_default_scanners_are_semgrep_and_gitleaks(self):
        assert [s.name for s in default_scanners()] == ["semgrep", "gitleaks"]
        assert all(isinstance(s, Scanner) for s in default_scanners())

    def test_scan_runs_then_parses(self):
        scanner = SemgrepScanner()
        with patch.object(SemgrepScanner, "run", return_value=SAMPLE_SEMGREP_JSON):
            records = scanner.scan("owner/repo", "REPO_ROOT")
        assert [r["tool"] for r in records] == ["semgrep"]
        assert records[0]["repo_full_name"] == "owner/repo"

    def test_a_new_scanner_only_needs_run_and_parse(self):
        class Fake(Scanner):
            name = "fake"

            def run(self, target_dir):
                return ["raw"]

            def parse(self, full_name, raw, repo_root):
                return [{"repo_full_name": full_name, "raw": raw[0], "root": repo_root}]

        assert Fake().scan("o/r", "/x") == [{"repo_full_name": "o/r", "raw": "raw", "root": "/x"}]
