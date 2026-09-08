"""DEPSCAN の到達可能性（reachability）ヒューリスティック判定。

「脆弱な依存が存在すること」と「その脆弱性が当該アプリで実際に到達・悪用可能で
あること」は別問題である（文献: 依存スキャナの偽陽性率97.5%、主因は到達不能
コードの検知）。本モジュールは、その第一段階として **import レベル**（＝脆弱な
パッケージがソースコード内で import/require/use されているか）のヒューリスティック
判定を行う。

**スコープと限界（意図的な設計判断）:**
- あくまで「パッケージがimportされているか」の判定であり、「脆弱な関数・APIが
  実際に呼び出されているか」（関数呼び出しレベルの解析）までは行わない。
  関数レベルの解析は (1) JS/TS・Dart・Ruby 等の正確な構文解析には専用パーサーが
  必要、(2) OSV の脆弱性データの大半には「どの関数が脆弱か」の構造化情報が
  無く判定基盤が無い、という2つの理由で本バージョンのスコープ外とする。
- パッケージ名からimport/require文中の識別子への変換は、エコシステムによって
  精度が大きく異なる。npm・Pub は変換規則がほぼ厳密（パッケージ名がそのまま
  import文字列になる）。PyPI・RubyGems・crates.io は一定のヒューリスティック
  正規化（ハイフン→アンダースコア等）で概ね対応できる。Maven・Packagist・Hex は
  パッケージ座標とソース内識別子（Javaパッケージ名・PHP名前空間・Elixirモジュール名）
  の対応関係が慣習的なものでしかなく、精度は最も低い（best-effort）。
"""
import re
from dataclasses import dataclass

# PyPI: パッケージ名とimport名が大きく異なる著名なケースのみ個別対応する
# （汎用的な解決は不可能なため、既知の主要パッケージに限定した補助的な措置）
_PYPI_IMPORT_OVERRIDES: dict[str, list[str]] = {
    "pyyaml": ["yaml"],
    "beautifulsoup4": ["bs4"],
    "pillow": ["pil"],
    "python-dateutil": ["dateutil"],
    "protobuf": ["google.protobuf"],
    "scikit-learn": ["sklearn"],
    "opencv-python": ["cv2"],
    "opencv-python-headless": ["cv2"],
    "python-dotenv": ["dotenv"],
    "python-jose": ["jose"],
    "pyjwt": ["jwt"],
    "msgpack-python": ["msgpack"],
}

# エコシステムごとの走査対象ファイル拡張子
SOURCE_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "PyPI": (".py",),
    "npm": (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
    "NuGet": (".cs",),
    "Pub": (".dart",),
    "Go": (".go",),
    "Maven": (".java", ".kt"),
    "RubyGems": (".rb",),
    "crates.io": (".rs",),
    "Packagist": (".php",),
    "Hex": (".ex", ".exs"),
}


@dataclass(frozen=True)
class ReachabilityResult:
    """到達可能性の判定結果。"""

    status: str  # "reachable" / "unreachable" / "unknown"


def _pypi_candidates(package_name: str) -> list[str]:
    key = package_name.lower()
    if key in _PYPI_IMPORT_OVERRIDES:
        return _PYPI_IMPORT_OVERRIDES[key]
    return [re.sub(r"[-_.]+", "_", key)]


def _rubygems_candidates(package_name: str) -> list[str]:
    return [package_name, package_name.replace("-", "_")]


def _crates_candidates(package_name: str) -> list[str]:
    return [package_name.replace("-", "_")]


def _packagist_candidates(package_name: str) -> list[str]:
    # "vendor/package" 形式。名前空間との対応は慣習的なものでしかないため、
    # ハイフンを除いたパッケージ名部分のみを緩く照合する（best-effort）
    segment = package_name.rsplit("/", 1)[-1]
    return [segment.replace("-", "")]


def _hex_candidates(package_name: str) -> list[str]:
    # Elixir のモジュール名慣習（snake_case → PascalCase）に変換する（best-effort）
    pascal = "".join(part.capitalize() for part in package_name.split("_"))
    return [pascal, package_name]


def _maven_candidates(package_name: str) -> list[str]:
    # "groupId:artifactId" 形式。groupId をJavaパッケージ名プレフィックスとして扱う
    group_id = package_name.split(":", 1)[0]
    return [group_id]


# エコシステムごとの候補名生成関数（デフォルトはパッケージ名そのまま）
_CANDIDATE_GENERATORS = {
    "PyPI": _pypi_candidates,
    "RubyGems": _rubygems_candidates,
    "crates.io": _crates_candidates,
    "Packagist": _packagist_candidates,
    "Hex": _hex_candidates,
    "Maven": _maven_candidates,
}


def _candidate_names(ecosystem: str, package_name: str) -> list[str]:
    generator = _CANDIDATE_GENERATORS.get(ecosystem)
    if generator is not None:
        return generator(package_name)
    # npm / Pub / Go / NuGet はパッケージ名がそのままソース内識別子になる
    return [package_name]


def _build_pattern(ecosystem: str, candidate: str) -> re.Pattern[str]:
    escaped = re.escape(candidate)

    if ecosystem == "PyPI":
        return re.compile(
            r"^\s*(?:from\s+" + escaped + r"(?:\.\S+)?\s+import\b"
            r"|import\s+" + escaped + r"(?:\.\S+)?(?:\s|,|$))",
            re.MULTILINE,
        )
    if ecosystem == "npm":
        return re.compile(
            r"""(?:require\(|from\s+|import\s*\()\s*['"]"""
            + escaped + r"""(?:/[^'"]*)?['"]""",
        )
    if ecosystem == "Pub":
        return re.compile(r"""import\s+['"]package:""" + escaped + r"/")
    if ecosystem == "RubyGems":
        return re.compile(
            r"""require(?:_relative)?\s+['"]""" + escaped + r"""(?:/[^'"]*)?['"]""",
        )
    if ecosystem == "Go":
        return re.compile(r'"' + escaped + r'(?:/[^"]*)?"')
    if ecosystem == "Maven":
        return re.compile(r"\bimport\s+(?:static\s+)?" + escaped + r"\.")
    if ecosystem == "crates.io":
        return re.compile(r"\b(?:use|extern\s+crate)\s+" + escaped + r"\b")
    if ecosystem == "Packagist":
        return re.compile(r"\buse\s+[^;]*" + escaped, re.IGNORECASE)
    if ecosystem == "Hex":
        return re.compile(r"\b(?:alias|import|use)\s+" + escaped + r"\b")
    if ecosystem == "NuGet":
        return re.compile(r"\busing\s+" + escaped + r"[;.]")

    raise ValueError(f"Unsupported ecosystem for reachability check: {ecosystem}")


def check_reachability(
    ecosystem: str, package_name: str, source_files: dict[str, str],
) -> str:
    """ソースファイル群の中で、指定パッケージが import/use されているか判定する。

    Args:
        ecosystem: DEPSCAN のエコシステム名（例: "PyPI"）
        package_name: パッケージ名（ロックファイルに記載の形式）
        source_files: {ファイルパス: 内容} の辞書。呼び出し側で該当拡張子
            （`SOURCE_EXTENSIONS[ecosystem]`）に絞り込んだものを渡す想定

    Returns:
        "reachable" / "unreachable" / "unknown"
        （source_files が空＝該当拡張子のソースを取得できなかった場合は "unknown"）
    """
    if not source_files:
        return "unknown"

    candidates = _candidate_names(ecosystem, package_name)
    patterns = [_build_pattern(ecosystem, c) for c in candidates]

    for content in source_files.values():
        if any(p.search(content) for p in patterns):
            return "reachable"

    return "unreachable"
