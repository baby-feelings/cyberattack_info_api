"""設定ファイルから、使っている言語・実行環境のバージョンを検出する（RUNTIME）。

GitHub への接続は呼び出し側（`crawler`）が担い、ここは「ファイルのパスと内容 → 検出結果」の
純粋な変換だけを持つ（副作用がなく、テストしやすい）。

検出する場所（`pinned` は、版を固定しているか）:

| ファイル | 検出するもの | pinned |
|---|---|---|
| `Dockerfile` の `FROM python:3.13` / `node:24` | Python・Node.js | True |
| `.python-version` / `.nvmrc` / `.node-version` / `.tool-versions` / `.fvmrc` | 各言語 | True |
| `.github/workflows/*.yml` の `python-version` `node-version` `flutter-version` | 各言語 | True |
| `firebase.json` の `"runtime": "python313"` / `"nodejs24"` | Python・Node.js | True |
| `package.json` の `engines.node` | Node.js | False（下限の指定） |
| `pubspec.yaml` の `environment.sdk` / `flutter` | Dart・Flutter | False（下限の指定） |
| `pyproject.toml` の `requires-python` | Python | False（下限の指定） |

外部のリポジトリのファイルを読むため、正規表現は入れ子の量指定子を避け、入力は1行ずつ、
長さを切って処理する（ReDoS 対策）。
"""
import json
import re
from dataclasses import dataclass

# 言語・実行環境の識別子（DB・API で共通に使う）
PYTHON = "python"
NODEJS = "nodejs"
FLUTTER = "flutter"
DART = "dart"
RUNTIMES = (PYTHON, NODEJS, FLUTTER, DART)

# 表示名
RUNTIME_LABELS = {
    PYTHON: "Python",
    NODEJS: "Node.js",
    FLUTTER: "Flutter",
    DART: "Dart",
}

# 1行・1ファイルあたりで見る長さの上限（異常に大きいファイルへの安全弁）
_MAX_LINE_LENGTH = 500
_MAX_FILE_LINES = 5000

# firebase.json の Python の runtime（`python313`）の数字の最小の桁数（メジャー1桁＋マイナー2桁）
_PYTHON_RUNTIME_MIN_DIGITS = 3

# バージョン文字列（先頭の演算子・v を除いた、`3.13` `3.13.5` `24` `24.x` など）
_VERSION_RE = re.compile(r"v?(\d{1,4})(?:\.(\d{1,4}|x|\*))?")
# 比較演算子（`>=3.13` `^3.13.0` `~22` など。先頭から取り除く）
_OPERATOR_CHARS = "<>=^~ \t\"'"

# Dockerfile の `FROM python:3.13-slim`（`--platform=...` を挟んでもよい）
_FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--\S{1,60}\s+)?(?:[\w.\-]{1,60}/){0,3}(python|node):(\S{1,60})",
    re.IGNORECASE,
)
# GitHub Actions の `python-version: "3.13"` / `node-version: [20, 22]`
_ACTIONS_RE = re.compile(
    r"^\s*-?\s*(python|node|flutter)-version\s*:\s*(.{1,200})$",
)
# firebase.json の `"runtime": "python313"` / `"nodejs24"`
_FIREBASE_RUNTIME_RE = re.compile(r"^(python|nodejs)(\d{2,4})$")
# .tool-versions の `python 3.13.5`
_TOOL_VERSIONS_RE = re.compile(r"^\s*(python|nodejs|node|flutter|dart)\s+(\S{1,40})")
# pyproject.toml の `requires-python = ">=3.13"`
_REQUIRES_PYTHON_RE = re.compile(r"^\s*requires-python\s*=\s*[\"']([^\"']{1,60})[\"']")
# pubspec.yaml の `sdk: ^3.13.0` / `flutter: ">=3.47.0"`
_PUBSPEC_RE = re.compile(r"^\s{1,8}(sdk|flutter)\s*:\s*[\"']?([^\"'\s#]{1,60})")


@dataclass(frozen=True)
class DetectedRuntime:
    """設定ファイルから検出した、使っている言語・実行環境のバージョン1件。"""

    runtime: str
    cycle: str
    source_path: str
    pinned: bool


def to_cycle(runtime: str, raw: str) -> str | None:
    """バージョン文字列を、系列（`3.13` / `24`）にそろえる。読み取れなければ None。

    - Node.js はメジャーのみ（`24` `v24.1.0` `24.x` → `24`）
    - Python・Flutter・Dart はメジャー.マイナー（`3.13` `3.13.5` `3.13-slim` → `3.13`）。
      マイナーが分からないもの（`3` `3.x`）は、どの系列か決められないため None
    - 比較演算子付きの下限（`>=3.13` `^3.5.0`）は、その下限を使う
    """
    text = raw.strip().lstrip(_OPERATOR_CHARS)[:_MAX_LINE_LENGTH]
    match = _VERSION_RE.match(text)
    if not match:
        return None
    major, minor = match.group(1), match.group(2)
    if runtime == NODEJS:
        return major
    if minor is None or not minor.isdigit():
        return None
    return f"{int(major)}.{int(minor)}"


def _runtime_for_tool(name: str) -> str:
    """`python` `node` `nodejs` といった表記を、識別子にそろえる。"""
    return NODEJS if name in ("node", "nodejs") else name


def _lines(content: str) -> list[str]:
    """内容を行に分ける（長い行・多すぎる行は切り捨てる）。"""
    return [line[:_MAX_LINE_LENGTH] for line in content.splitlines()[:_MAX_FILE_LINES]]


def _detect_dockerfile(path: str, content: str) -> list[DetectedRuntime]:
    found = []
    for line in _lines(content):
        match = _FROM_RE.match(line)
        if not match:
            continue
        runtime = _runtime_for_tool(match.group(1).lower())
        cycle = to_cycle(runtime, match.group(2))
        if cycle:
            found.append(DetectedRuntime(runtime, cycle, path, True))
    return found


def _detect_single_version_file(
    runtime: str, path: str, content: str,
) -> list[DetectedRuntime]:
    """`.python-version` `.nvmrc` のような、先頭の1行にバージョンだけを書くファイル。"""
    lines = _lines(content)
    cycle = to_cycle(runtime, lines[0]) if lines else None
    return [DetectedRuntime(runtime, cycle, path, True)] if cycle else []


def _detect_tool_versions(path: str, content: str) -> list[DetectedRuntime]:
    found = []
    for line in _lines(content):
        match = _TOOL_VERSIONS_RE.match(line)
        if not match:
            continue
        runtime = _runtime_for_tool(match.group(1))
        cycle = to_cycle(runtime, match.group(2))
        if cycle:
            found.append(DetectedRuntime(runtime, cycle, path, True))
    return found


def _detect_workflow(path: str, content: str) -> list[DetectedRuntime]:
    found = []
    for line in _lines(content):
        match = _ACTIONS_RE.match(line)
        if not match:
            continue
        runtime = _runtime_for_tool(match.group(1))
        # `["3.12", "3.13"]` のような一覧は、要素ごとに読む（`${{ matrix.x }}` は読み取れない）
        value = match.group(2).split("#", 1)[0].strip().strip("[]")
        for item in value.split(","):
            cycle = to_cycle(runtime, item.strip().strip("\"'"))
            if cycle:
                found.append(DetectedRuntime(runtime, cycle, path, True))
    return found


def _detect_firebase(path: str, content: str) -> list[DetectedRuntime]:
    """`firebase.json` の `functions[].runtime`（`python313` → 3.13、`nodejs24` → 24）。"""
    try:
        data = json.loads(content)
    except ValueError:
        return []
    functions = data.get("functions") if isinstance(data, dict) else None
    entries = functions if isinstance(functions, list) else [functions]
    found = []
    for entry in entries:
        runtime_text = entry.get("runtime") if isinstance(entry, dict) else None
        match = _FIREBASE_RUNTIME_RE.match(runtime_text) if isinstance(runtime_text, str) else None
        if not match:
            continue
        runtime, digits = match.group(1), match.group(2)
        if runtime == NODEJS:
            found.append(DetectedRuntime(NODEJS, str(int(digits)), path, True))
        elif len(digits) >= _PYTHON_RUNTIME_MIN_DIGITS:
            # python313 → 3.13（先頭1桁がメジャー、残りがマイナー）
            found.append(DetectedRuntime(PYTHON, f"{digits[0]}.{int(digits[1:])}", path, True))
    return found


def _detect_package_json(path: str, content: str) -> list[DetectedRuntime]:
    """`package.json` の `engines.node`（下限の指定のため pinned=False）。"""
    try:
        data = json.loads(content)
    except ValueError:
        return []
    engines = data.get("engines") if isinstance(data, dict) else None
    node = engines.get("node") if isinstance(engines, dict) else None
    cycle = to_cycle(NODEJS, node) if isinstance(node, str) else None
    return [DetectedRuntime(NODEJS, cycle, path, False)] if cycle else []


def _detect_pubspec(path: str, content: str) -> list[DetectedRuntime]:
    """`pubspec.yaml` の `environment.sdk`（Dart）・`environment.flutter`（下限の指定）。"""
    found = []
    for line in _lines(content):
        match = _PUBSPEC_RE.match(line)
        if not match:
            continue
        runtime = DART if match.group(1) == "sdk" else FLUTTER
        cycle = to_cycle(runtime, match.group(2))
        if cycle:
            found.append(DetectedRuntime(runtime, cycle, path, False))
    return found


def _detect_pyproject(path: str, content: str) -> list[DetectedRuntime]:
    for line in _lines(content):
        match = _REQUIRES_PYTHON_RE.match(line)
        if match:
            cycle = to_cycle(PYTHON, match.group(1))
            return [DetectedRuntime(PYTHON, cycle, path, False)] if cycle else []
    return []


def _detect_fvmrc(path: str, content: str) -> list[DetectedRuntime]:
    """`.fvmrc`（FVM）の `{"flutter": "3.47.6"}`。"""
    try:
        data = json.loads(content)
    except ValueError:
        return []
    value = data.get("flutter") if isinstance(data, dict) else None
    cycle = to_cycle(FLUTTER, value) if isinstance(value, str) else None
    return [DetectedRuntime(FLUTTER, cycle, path, True)] if cycle else []


# ファイル名（末尾）→ 検出関数
_BY_BASENAME = {
    ".python-version": lambda p, c: _detect_single_version_file(PYTHON, p, c),
    ".nvmrc": lambda p, c: _detect_single_version_file(NODEJS, p, c),
    ".node-version": lambda p, c: _detect_single_version_file(NODEJS, p, c),
    ".tool-versions": _detect_tool_versions,
    ".fvmrc": _detect_fvmrc,
    "firebase.json": _detect_firebase,
    "package.json": _detect_package_json,
    "pubspec.yaml": _detect_pubspec,
    "pyproject.toml": _detect_pyproject,
}


def _is_dockerfile(basename: str) -> bool:
    """`Dockerfile` `Dockerfile.prod` `api.Dockerfile` のいずれか。"""
    return (
        basename == "Dockerfile"
        or basename.startswith("Dockerfile.")
        or basename.endswith(".Dockerfile")
    )


def _is_workflow(path: str) -> bool:
    """GitHub Actions のワークフローファイル。"""
    return path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml"))


def is_candidate(path: str) -> bool:
    """検出の対象になりうるファイルのパスか（取得するファイルを絞るための判定）。"""
    basename = path.rsplit("/", 1)[-1]
    if basename in _BY_BASENAME:
        return True
    return _is_dockerfile(basename) or _is_workflow(path)


def detect_runtimes(path: str, content: str) -> list[DetectedRuntime]:
    """ファイルのパスと内容から、使っている言語・実行環境を検出する（重複は除く）。"""
    basename = path.rsplit("/", 1)[-1]
    if basename in _BY_BASENAME:
        found = _BY_BASENAME[basename](path, content)
    elif _is_dockerfile(basename):
        found = _detect_dockerfile(path, content)
    elif _is_workflow(path):
        found = _detect_workflow(path, content)
    else:
        found = []
    # 同じファイルに同じ版が複数回出ても、1件にまとめる（出現順は保つ）
    return list(dict.fromkeys(found))
