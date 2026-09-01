"""依存ライブラリロックファイルのパーサー群（DEPSCAN 機能）。

言語・エコシステムごとのロックファイルをパースし、共通形式 `DependencyRef`
（ecosystem, name, version）のリストへ正規化する。
"""
from collections.abc import Callable

from app.dependency_parsers.base import DependencyRef
from app.dependency_parsers.cargo_lock import parse_cargo_lock
from app.dependency_parsers.composer_lock import parse_composer_lock
from app.dependency_parsers.gemfile_lock import parse_gemfile_lock
from app.dependency_parsers.go_sum import parse_go_sum
from app.dependency_parsers.mix_lock import parse_mix_lock
from app.dependency_parsers.package_lock_json import parse_package_lock_json
from app.dependency_parsers.packages_lock_json import parse_packages_lock_json
from app.dependency_parsers.pom_xml import parse_pom_xml
from app.dependency_parsers.pubspec_lock import parse_pubspec_lock
from app.dependency_parsers.requirements_txt import parse_requirements_txt

# ファイル名（basename） → パーサー関数
# NOTE: dict の走査順に依存するため、より具体的なファイル名を先に定義する
# （例: "packages.lock.json" は "package-lock.json" と別物）
PARSERS: dict[str, Callable[[str], list[DependencyRef]]] = {
    "requirements.txt": parse_requirements_txt,
    "package-lock.json": parse_package_lock_json,
    "packages.lock.json": parse_packages_lock_json,
    "pubspec.lock": parse_pubspec_lock,
    "go.sum": parse_go_sum,
    "pom.xml": parse_pom_xml,
    "Gemfile.lock": parse_gemfile_lock,
    "Cargo.lock": parse_cargo_lock,
    "composer.lock": parse_composer_lock,
    "mix.lock": parse_mix_lock,
}

# 検出対象のロックファイル名（Git Tree API のパス末尾との照合に使う）
LOCKFILE_FILENAMES = frozenset(PARSERS.keys())


def parse_manifest(filename: str, content: str) -> list[DependencyRef]:
    """ファイル名から対応するパーサーを選び、内容をパースする。

    Args:
        filename: ファイル名（basename。例: "requirements.txt"）
        content: ファイルの中身

    Returns:
        DependencyRef のリスト（未対応ファイルの場合は空リスト）
    """
    parser = PARSERS.get(filename)
    if parser is None:
        return []
    return parser(content)


__all__ = ["DependencyRef", "PARSERS", "LOCKFILE_FILENAMES", "parse_manifest"]
