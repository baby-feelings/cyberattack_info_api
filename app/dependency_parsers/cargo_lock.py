"""Cargo.lock（Rust / crates.io）パーサー。

TOML 形式。Python 3.11+ は標準ライブラリ tomllib、3.10 は tomli（依存追加）を使用する。
"""
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from app.dependency_parsers.base import DependencyRef


def parse_cargo_lock(content: str) -> list[DependencyRef]:
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        return []

    refs: list[DependencyRef] = []
    for package in data.get("package", []):
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if name and version:
            refs.append(DependencyRef("crates.io", name, version))
    return refs
