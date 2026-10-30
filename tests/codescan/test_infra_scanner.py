"""app.codescan.scanners.InfraScanner（インフラ設定の診断。Issue #400）のテスト。"""
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")

from app.codescan import scanners  # noqa: E402
from app.codescan.scanners import InfraScanner, default_scanners  # noqa: E402

GOOD_DOCKERFILE = "FROM python:3.13-slim\nRUN useradd -m app\nUSER app\n"


def _write(root, relative, text):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class TestRun:
    def test_finds_the_infrastructure_files_with_relative_slash_paths(self, tmp_path):
        _write(tmp_path, "firestore.rules", "allow read: if true;")
        _write(tmp_path, "backend/Dockerfile", GOOD_DOCKERFILE)
        _write(tmp_path, "backend/Dockerfile.dev", GOOD_DOCKERFILE)
        _write(tmp_path, "web.Dockerfile", GOOD_DOCKERFILE)
        _write(tmp_path, "deploy/docker-compose.prod.yml", "services: {}")
        _write(tmp_path, "compose.yaml", "services: {}")
        _write(tmp_path, "firebase.json", "{}")
        _write(tmp_path, "storage.rules", "")
        _write(tmp_path, "database.rules.json", "{}")

        found = [path for path, _ in InfraScanner().run(str(tmp_path))]

        assert sorted(found) == sorted([
            "firestore.rules", "backend/Dockerfile", "backend/Dockerfile.dev", "web.Dockerfile",
            "deploy/docker-compose.prod.yml", "compose.yaml", "firebase.json", "storage.rules",
            "database.rules.json",
        ])

    def test_ignores_other_files_and_dependency_directories(self, tmp_path):
        _write(tmp_path, "README.md", "Dockerfile")
        _write(tmp_path, "src/app.yml", "privileged: true")
        _write(tmp_path, "node_modules/pkg/Dockerfile", "FROM python")
        _write(tmp_path, ".git/Dockerfile", "FROM python")
        _write(tmp_path, "vendor/firestore.rules", "allow read: if true;")

        assert InfraScanner().run(str(tmp_path)) == []

    def test_skips_files_over_the_size_limit(self, tmp_path):
        _write(tmp_path, "Dockerfile", "FROM python\n" + "#" * (scanners._IAC_MAX_FILE_BYTES + 1))
        assert InfraScanner().run(str(tmp_path)) == []

    def test_caps_the_number_of_files(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scanners, "_IAC_MAX_FILES", 2)
        for i in range(5):
            _write(tmp_path, f"d{i}/Dockerfile", GOOD_DOCKERFILE)

        assert len(InfraScanner().run(str(tmp_path))) == 2

    def test_unreadable_files_are_skipped(self, tmp_path):
        _write(tmp_path, "Dockerfile", GOOD_DOCKERFILE)
        _write(tmp_path, "firebase.json", "{}")
        real_open = open

        def flaky_open(path, *args, **kwargs):
            if str(path).endswith("firebase.json"):
                raise PermissionError("denied")
            return real_open(path, *args, **kwargs)

        from unittest.mock import patch
        with patch("builtins.open", flaky_open):
            found = [p for p, _ in InfraScanner().run(str(tmp_path))]

        assert found == ["Dockerfile"]

    def test_an_empty_directory_has_nothing_to_scan(self, tmp_path):
        assert InfraScanner().run(str(tmp_path)) == []


class TestParse:
    def test_turns_issues_into_code_finding_records(self):
        raw = [("firestore.rules", "match /x {\n  allow read, write: if true;\n}\n")]

        [record] = InfraScanner().parse("owner/repo", raw, "/root")

        assert record["repo_full_name"] == "owner/repo"
        assert record["file_path"] == "firestore.rules"
        assert (record["line_start"], record["line_end"]) == (2, 2)
        # 他ツールの rule_id と衝突しないよう、接頭辞を付ける
        assert record["rule_id"] == "iac:firebase-open-write"
        assert record["severity"] == "ERROR"
        assert record["cwe_ids"] == ["CWE-862"]
        assert record["tool"] == "iac"
        assert "対策" in record["message"]
        assert record["code_snippet"] == "allow read, write: if true;"
        # 設定の不備のため、CVSS は推定しない
        assert (record["cvss_score"], record["cvss_vector"]) == (None, None)
        assert record["detected_at"] is not None

    def test_secret_values_never_reach_the_record(self):
        raw = [("Dockerfile", "FROM python:3.13-slim\nUSER app\nENV DB_PASSWORD=hunter2\n")]

        [record] = InfraScanner().parse("o/r", raw, "/root")

        assert "hunter2" not in repr(record)
        assert record["code_snippet"] == "ENV DB_PASSWORD=***"

    def test_each_file_kind_uses_its_own_rules(self):
        raw = [
            ("firebase.json", '{"hosting": {"public": "."}}'),
            ("docker-compose.yml", "services:\n  a:\n    privileged: true\n"),
            ("database.rules.json", '{".write": true}'),
        ]

        rules = [r["rule_id"] for r in InfraScanner().parse("o/r", raw, "/root")]

        assert rules == [
            "iac:firebase-hosting-public-root", "iac:compose-privileged", "iac:firebase-open-write",
        ]

    def test_files_of_an_unknown_kind_are_ignored_and_a_clean_file_has_no_records(self):
        raw = [("README.md", "privileged: true"), ("Dockerfile", GOOD_DOCKERFILE)]
        assert InfraScanner().parse("o/r", raw, "/root") == []

    def test_a_long_snippet_is_cut(self):
        long_line = "allow write: if true; " + "x" * 5000
        [record] = InfraScanner().parse("o/r", [("firestore.rules", long_line)], "/root")
        assert len(record["code_snippet"]) <= scanners._MAX_SNIPPET_LEN


class TestScan:
    def test_scan_walks_the_directory_and_returns_records(self, tmp_path):
        _write(tmp_path, "firestore.rules", "allow write: if true;")

        records = InfraScanner().scan("o/r", str(tmp_path))

        assert [r["rule_id"] for r in records] == ["iac:firebase-open-write"]

    def test_it_is_one_of_the_default_scanners(self):
        assert "iac" in [s.name for s in default_scanners()]
