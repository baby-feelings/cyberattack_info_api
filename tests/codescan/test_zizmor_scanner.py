"""app.codescan.scanners.ZizmorScanner（GitHub Actions ワークフローの診断。Issue #397）のテスト。

サンプルの出力は、実際の zizmor 1.31 の JSON 形式（`--format json`）に合わせている。
"""
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")

import json  # noqa: E402
import subprocess  # noqa: E402
from unittest.mock import patch  # noqa: E402

import pytest  # noqa: E402

from app.codescan.scanners import ZizmorScanner  # noqa: E402


def _finding(*, ident="unpinned-uses", severity="High", path="./.github/workflows/ci.yml",
             row=7, end_row=None, annotation="action is not pinned to a hash",
             feature="actions/checkout@v4", ignored=False, kind="Primary", persona="Regular"):
    """zizmor の指摘1件（実際の出力と同じ構造）。"""
    return {
        "ident": ident,
        "desc": "unpinned action reference",
        "url": f"https://docs.zizmor.sh/audits/#{ident}",
        "determinations": {"confidence": "High", "severity": severity, "persona": persona},
        "locations": [{
            "symbolic": {
                "key": {"Local": {"verbatim_path": path}},
                "annotation": annotation,
                "route": {"route": [{"Key": "jobs"}]},
                "feature_kind": "Normal",
                "kind": kind,
            },
            "concrete": {
                "location": {
                    "start_point": {"row": row, "column": 14},
                    "end_point": {"row": row if end_row is None else end_row, "column": 47},
                    "offset_span": {"start": 1, "end": 2},
                },
                "feature": feature,
                "comments": [],
            },
        }],
        "ignored": ignored,
    }


def _completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class TestRun:
    def test_runs_offline_with_json_output_in_the_repo_directory(self):
        with patch(
            "app.codescan.scanners.subprocess.run", return_value=_completed("[]"),
        ) as mock_run:
            ZizmorScanner().run("/tmp/repo")

        args = mock_run.call_args.args[0]
        assert args[0] == "zizmor"
        # ネットワークに接続しない（トークンも渡さない）
        assert "--offline" in args
        # self-hosted-runner は auditor の指摘のため、auditor で実行し、parse で絞る
        assert args[args.index("--persona") + 1] == "auditor"
        assert mock_run.call_args.kwargs["encoding"] == "utf-8"
        assert args[args.index("--format") + 1] == "json"
        # 終了コードで失敗扱いにしない（検知があっても出力を読む）
        assert "--no-exit-codes" in args
        # 作業ディレクトリを対象にして、パスをリポジトリ基準の相対にする
        assert args[-1] == "."
        assert mock_run.call_args.kwargs["cwd"] == "/tmp/repo"
        assert mock_run.call_args.kwargs["timeout"] > 0

    def test_returns_the_parsed_findings(self):
        payload = [_finding()]
        with patch(
            "app.codescan.scanners.subprocess.run", return_value=_completed(json.dumps(payload)),
        ):
            assert ZizmorScanner().run("/tmp/repo") == payload

    def test_no_findings_is_an_empty_list(self):
        with patch("app.codescan.scanners.subprocess.run", return_value=_completed("[]")):
            assert ZizmorScanner().run("/tmp/repo") == []

    def test_repo_without_workflows_is_not_an_error(self):
        # ワークフローが無いリポジトリ: 終了コード3・標準出力なし。検知なしとして扱う
        stderr = "fatal: no audit was performed\nerror: no inputs collected\n"
        with patch(
            "app.codescan.scanners.subprocess.run",
            return_value=_completed(stderr=stderr, returncode=3),
        ):
            assert ZizmorScanner().run("/tmp/repo") == []

    def test_tool_failure_raises_instead_of_looking_like_no_findings(self):
        # 検知0件として扱うと、既存の検知を「解決済み」にしてしまうため、例外にする
        with patch(
            "app.codescan.scanners.subprocess.run",
            return_value=_completed(stderr="panic: something broke", returncode=1),
        ), pytest.raises(OSError, match="zizmor failed"):
            ZizmorScanner().run("/tmp/repo")

    def test_invalid_json_raises(self):
        with patch(
            "app.codescan.scanners.subprocess.run", return_value=_completed("not json"),
        ), pytest.raises(json.JSONDecodeError):
            ZizmorScanner().run("/tmp/repo")

    def test_non_list_json_is_treated_as_empty(self):
        with patch("app.codescan.scanners.subprocess.run", return_value=_completed("{}")):
            assert ZizmorScanner().run("/tmp/repo") == []


class TestParse:
    def _parse(self, raw, repo_root="/tmp/repo"):
        return ZizmorScanner().parse("u/app", raw, repo_root)

    def test_builds_a_code_finding_record(self):
        [rec] = self._parse([_finding()])

        assert rec["repo_full_name"] == "u/app"
        assert rec["file_path"] == ".github/workflows/ci.yml"
        assert rec["rule_id"] == "zizmor:unpinned-uses"
        assert rec["tool"] == "zizmor"
        assert rec["code_snippet"] == "actions/checkout@v4"
        assert rec["detected_at"] is not None

    def test_line_numbers_are_converted_from_zero_based(self):
        [rec] = self._parse([_finding(row=7, end_row=9)])

        assert (rec["line_start"], rec["line_end"]) == (8, 10)

    @pytest.mark.parametrize(
        ("zizmor_severity", "expected"),
        [("High", "ERROR"), ("Medium", "WARNING"), ("Low", "INFO"),
         ("Informational", "INFO"), ("Unknown", "INFO"), ("", "INFO")],
    )
    def test_severity_is_mapped_to_the_codescan_scale(self, zizmor_severity, expected):
        [rec] = self._parse([_finding(severity=zizmor_severity)])

        assert rec["severity"] == expected

    def test_message_has_description_annotation_fix_hint_and_docs_url(self):
        [rec] = self._parse([_finding()])

        assert "unpinned action reference" in rec["message"]
        assert "action is not pinned to a hash" in rec["message"]
        assert "コミットSHA" in rec["message"]  # 修正方法
        assert "https://docs.zizmor.sh/audits/#unpinned-uses" in rec["message"]

    def test_unknown_ident_has_no_fix_hint_but_still_a_message(self):
        [rec] = self._parse([_finding(ident="some-new-audit")])

        assert "対策:" not in rec["message"]
        assert "unpinned action reference" in rec["message"]

    @pytest.mark.parametrize("ident", [
        "unpinned-uses", "excessive-permissions", "dangerous-triggers",
        "template-injection", "self-hosted-runner",
    ])
    def test_the_issues_target_audits_have_fix_hints(self, ident):
        [rec] = self._parse([_finding(ident=ident)])

        assert "対策:" in rec["message"]

    def test_no_cvss_or_cwe_is_guessed(self):
        [rec] = self._parse([_finding()])

        assert rec["cvss_score"] is None and rec["cvss_vector"] is None
        assert rec["cwe_ids"] == [] and rec["owasp_categories"] == []

    def test_self_hosted_runner_is_kept_although_it_is_an_auditor_finding(self):
        [rec] = self._parse([
            _finding(ident="self-hosted-runner", severity="Medium", persona="Auditor"),
        ])

        assert rec["rule_id"] == "zizmor:self-hosted-runner"
        assert rec["severity"] == "WARNING"
        assert "対策:" in rec["message"]

    @pytest.mark.parametrize("persona", ["Auditor", "Pedantic"])
    def test_other_auditor_and_pedantic_findings_are_noise_and_skipped(self, persona):
        assert self._parse([_finding(ident="concurrency-limits", persona=persona)]) == []

    def test_regular_findings_are_kept_even_when_run_in_auditor_mode(self):
        # auditor で実行しても、regular の指摘（本来の検知）は、そのまま残る
        assert len(self._parse([_finding(persona="Regular")])) == 1

    def test_ignored_findings_are_skipped(self):
        # `# zizmor: ignore[...]` で意図的に除外されたもの
        assert self._parse([_finding(ignored=True)]) == []

    def test_snippet_is_not_stored_for_credential_findings(self):
        [rec] = self._parse([
            _finding(ident="hardcoded-container-credentials", feature="password: hunter2"),
        ])

        assert rec["code_snippet"] == ""
        assert "hunter2" not in json.dumps(rec, default=str)

    def test_long_snippet_is_truncated(self):
        [rec] = self._parse([_finding(feature="x" * 5000)])

        assert len(rec["code_snippet"]) == 2000

    def test_windows_style_and_absolute_paths_are_made_relative(self):
        absolute = self._parse(
            [_finding(path="/tmp/repo/.github/workflows/ci.yml")], repo_root="/tmp/repo",
        )
        backslashes = self._parse([_finding(path=".github\\workflows\\ci.yml")])

        assert absolute[0]["file_path"] == ".github/workflows/ci.yml"
        assert backslashes[0]["file_path"] == ".github/workflows/ci.yml"

    def test_path_never_contains_a_temp_directory_name(self):
        # 一時ディレクトリ名が file_path に残ると、検知の一意キーが毎回変わり重複が増える
        [rec] = self._parse([_finding(path="/tmp/tmpab12cd/repo/.github/workflows/ci.yml")],
                            repo_root="/tmp/tmpab12cd/repo")

        assert "tmpab12cd" not in rec["file_path"]

    def test_uses_the_primary_location(self):
        finding = _finding(kind="Related", row=1)
        finding["locations"].append(_finding(kind="Primary", row=20)["locations"][0])

        [rec] = self._parse([finding])

        assert rec["line_start"] == 21

    def test_falls_back_to_the_first_location_when_none_is_primary(self):
        [rec] = self._parse([_finding(kind="Related", row=3)])

        assert rec["line_start"] == 4

    def test_findings_without_a_local_file_or_location_are_skipped(self):
        remote = _finding()
        remote["locations"][0]["symbolic"]["key"] = {"Remote": {"slug": "o/r"}}
        no_location = _finding()
        no_location["locations"] = []

        assert self._parse([remote, no_location]) == []

    def test_empty_output_gives_no_records(self):
        assert self._parse([]) == []


class TestScan:
    def test_scan_runs_then_parses(self):
        payload = [_finding(), _finding(ident="template-injection", row=9)]
        with patch.object(ZizmorScanner, "run", return_value=payload):
            records = ZizmorScanner().scan("u/app", "/tmp/repo")

        assert [r["rule_id"] for r in records] == [
            "zizmor:unpinned-uses", "zizmor:template-injection",
        ]
