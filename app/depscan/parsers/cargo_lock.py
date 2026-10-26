"""Cargo.lock（Rust / crates.io）パーサー。

TOML 形式。標準ライブラリ tomllib（Python 3.11+）で読む。
"""
import tomllib

from app.depscan.parsers.base import DependencyRef


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
