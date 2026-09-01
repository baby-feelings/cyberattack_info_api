"""composer.lock（PHP / Packagist）パーサー。"""
import json

from app.depscan.parsers.base import DependencyRef


def parse_composer_lock(content: str) -> list[DependencyRef]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    refs: list[DependencyRef] = []
    for key in ("packages", "packages-dev"):
        for pkg in data.get(key) or []:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            version = (pkg.get("version") or "").lstrip("v")
            if name and version:
                refs.append(DependencyRef("Packagist", name, version))
    return refs
