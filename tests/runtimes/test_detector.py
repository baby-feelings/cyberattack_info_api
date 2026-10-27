"""app.runtimes.detector（設定ファイルからの使用バージョンの検出）のテスト。"""
import time

import pytest

from app.runtimes.detector import (
    DART,
    FLUTTER,
    NODEJS,
    PYTHON,
    DetectedRuntime,
    detect_runtimes,
    is_candidate,
    to_cycle,
)


class TestToCycle:
    @pytest.mark.parametrize("runtime,raw,expected", [
        (PYTHON, "3.13", "3.13"),
        (PYTHON, "3.13.5", "3.13"),
        (PYTHON, "3.13-slim", "3.13"),
        (PYTHON, ">=3.13", "3.13"),
        (PYTHON, "3.9", "3.9"),
        (NODEJS, "24", "24"),
        (NODEJS, "v24.1.0", "24"),
        (NODEJS, "24.x", "24"),
        (NODEJS, ">=22", "22"),
        (NODEJS, "^20.0.0 || >=22", "20"),
        (FLUTTER, "3.47.6", "3.47"),
        (DART, "^3.13.0", "3.13"),
    ])
    def test_normalizes(self, runtime, raw, expected):
        assert to_cycle(runtime, raw) == expected

    @pytest.mark.parametrize("runtime,raw", [
        (PYTHON, "3"),            # マイナーが分からない
        (PYTHON, "3.x"),
        (PYTHON, "latest"),
        (PYTHON, "${{ matrix.python }}"),
        (NODEJS, "lts/*"),
        (NODEJS, ""),
        (FLUTTER, "stable"),
    ])
    def test_returns_none_when_unreadable(self, runtime, raw):
        assert to_cycle(runtime, raw) is None


class TestIsCandidate:
    @pytest.mark.parametrize("path", [
        "Dockerfile", "deploy/Dockerfile.prod", "api.Dockerfile", ".python-version", ".nvmrc",
        "functions/package.json", "firebase.json", "pubspec.yaml", "pyproject.toml",
        ".github/workflows/ci.yml", ".github/workflows/deploy.yaml", ".fvmrc", ".tool-versions",
    ])
    def test_targets(self, path):
        assert is_candidate(path)

    @pytest.mark.parametrize("path", [
        "README.md", "src/main.py", "docs/workflows/ci.yml", ".github/CODEOWNERS",
    ])
    def test_non_targets(self, path):
        assert not is_candidate(path)


class TestDockerfile:
    def test_detects_python_and_node_from_stages(self):
        content = (
            "FROM node:24-alpine AS build\nRUN npm ci\n"
            "FROM --platform=linux/amd64 python:3.13-slim\nCOPY . .\n"
        )
        assert detect_runtimes("Dockerfile", content) == [
            DetectedRuntime(NODEJS, "24", "Dockerfile", True),
            DetectedRuntime(PYTHON, "3.13", "Dockerfile", True),
        ]

    def test_ignores_other_images_and_unversioned_tags(self):
        assert detect_runtimes("Dockerfile", "FROM caddy:2-alpine\nFROM python:3-slim\n") == []

    def test_registry_prefix(self):
        found = detect_runtimes("Dockerfile", "FROM docker.io/library/python:3.12\n")
        assert found == [DetectedRuntime(PYTHON, "3.12", "Dockerfile", True)]


class TestVersionFiles:
    def test_python_version_file(self):
        assert detect_runtimes(".python-version", "3.13.5\n") == [
            DetectedRuntime(PYTHON, "3.13", ".python-version", True)]

    def test_nvmrc_and_node_version(self):
        assert detect_runtimes(".nvmrc", "v24.1.0\n")[0].cycle == "24"
        assert detect_runtimes("app/.node-version", "22\n")[0].cycle == "22"
        assert detect_runtimes(".nvmrc", "lts/*\n") == []

    def test_tool_versions(self):
        found = detect_runtimes(".tool-versions", "python 3.13.5\nnodejs 24.1.0\nflutter 3.47.6\n")
        assert [(d.runtime, d.cycle) for d in found] == [
            (PYTHON, "3.13"), (NODEJS, "24"), (FLUTTER, "3.47")]

    def test_fvmrc(self):
        assert detect_runtimes(".fvmrc", '{"flutter": "3.47.6"}') == [
            DetectedRuntime(FLUTTER, "3.47", ".fvmrc", True)]
        assert detect_runtimes(".fvmrc", "not json") == []


class TestWorkflow:
    _PATH = ".github/workflows/ci.yml"

    def test_scalar_and_quoted_versions(self):
        content = (
            "      - uses: actions/setup-python@v7\n"
            "        with:\n          python-version: \"3.13\"\n"
            "      - uses: actions/setup-node@v7\n"
            "        with:\n          node-version: 24\n"
            "      - uses: subosito/flutter-action@v2\n"
            "        with:\n          flutter-version: 3.47.6\n"
        )
        assert [(d.runtime, d.cycle) for d in detect_runtimes(self._PATH, content)] == [
            (PYTHON, "3.13"), (NODEJS, "24"), (FLUTTER, "3.47")]

    def test_inline_list_and_comment(self):
        content = "        python-version: [\"3.12\", \"3.13\"]  # 対応する版\n"
        assert [d.cycle for d in detect_runtimes(self._PATH, content)] == ["3.12", "3.13"]

    def test_matrix_expression_is_skipped(self):
        content = "          python-version: ${{ matrix.python-version }}\n"
        assert detect_runtimes(self._PATH, content) == []

    def test_duplicates_are_merged(self):
        content = "python-version: 3.13\n  python-version: 3.13\n"
        assert len(detect_runtimes(self._PATH, content)) == 1


class TestFirebase:
    def test_object_and_array_forms(self):
        obj = '{"functions": {"runtime": "python313"}}'
        arr = '{"functions": [{"runtime": "nodejs24"}, {"runtime": "python312"}]}'
        assert detect_runtimes("firebase.json", obj) == [
            DetectedRuntime(PYTHON, "3.13", "firebase.json", True)]
        assert [(d.runtime, d.cycle) for d in detect_runtimes("firebase.json", arr)] == [
            (NODEJS, "24"), (PYTHON, "3.12")]

    def test_ignores_unknown_runtime_and_invalid_json(self):
        assert detect_runtimes("firebase.json", '{"functions": {"runtime": "go121"}}') == []
        assert detect_runtimes("firebase.json", "{") == []
        assert detect_runtimes("firebase.json", '{"hosting": {}}') == []


class TestLowerBounds:
    """下限の指定は、実際に動いている版とは限らないため pinned=False で検出する。"""

    def test_package_json_engines(self):
        found = detect_runtimes("functions/package.json", '{"engines": {"node": ">=22"}}')
        assert found == [DetectedRuntime(NODEJS, "22", "functions/package.json", False)]
        assert detect_runtimes("package.json", '{"name": "x"}') == []

    def test_pubspec(self):
        content = "environment:\n  sdk: ^3.13.0\n  flutter: \">=3.47.0\"\n"
        assert detect_runtimes("pubspec.yaml", content) == [
            DetectedRuntime(DART, "3.13", "pubspec.yaml", False),
            DetectedRuntime(FLUTTER, "3.47", "pubspec.yaml", False),
        ]

    def test_pyproject(self):
        content = '[project]\nrequires-python = ">=3.13"\n'
        assert detect_runtimes("pyproject.toml", content) == [
            DetectedRuntime(PYTHON, "3.13", "pyproject.toml", False)]


class TestEdgeCases:
    def test_empty_single_version_file(self):
        assert detect_runtimes(".python-version", "") == []

    def test_tool_versions_skips_unreadable_lines(self):
        content = "# comment\npython latest\nruby 3.3.0\nnodejs 24.1.0\n"
        assert [(d.runtime, d.cycle) for d in detect_runtimes(".tool-versions", content)] == [
            (NODEJS, "24")]

    def test_non_object_json_is_ignored(self):
        for path in ("package.json", "firebase.json", ".fvmrc"):
            assert detect_runtimes(path, "[1, 2]") == []
        assert detect_runtimes("package.json", "{") == []

    def test_pyproject_without_requires_python(self):
        assert detect_runtimes("pyproject.toml", "[project]\nname = 'x'\n") == []

    def test_pyproject_with_unreadable_requires_python(self):
        assert detect_runtimes("pyproject.toml", 'requires-python = "latest"\n') == []

    def test_python_digits_from_firebase_with_two_digits_are_ignored(self):
        assert detect_runtimes("firebase.json", '{"functions": {"runtime": "python3"}}') == []


class TestRobustness:
    def test_unknown_file_returns_nothing(self):
        assert detect_runtimes("README.md", "python-version: 3.13") == []

    def test_long_lines_do_not_hang(self):
        """異常に長い行でも、正規表現が長時間かからない（ReDoS 対策）。"""
        hostile = "FROM " + "a/" * 5000 + "python:" + "9" * 100000 + "\n"
        hostile += "python-version: " + "[" * 100000 + "\n"
        hostile += "  sdk: " + "^" * 100000 + "\n"
        started = time.monotonic()
        for path in ("Dockerfile", ".github/workflows/x.yml", "pubspec.yaml"):
            detect_runtimes(path, hostile)
        assert time.monotonic() - started < 2.0
