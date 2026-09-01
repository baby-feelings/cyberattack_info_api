"""go.sum（Go）パーサー。

各行は "module version hash" または "module version/go.mod hash" の形式。
同一 module/version の重複行（本体 + go.mod）は1件に統合する。
"""
from app.dependency_parsers.base import DependencyRef


def parse_go_sum(content: str) -> list[DependencyRef]:
    seen: set[tuple[str, str]] = set()
    refs: list[DependencyRef] = []
    for line in content.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        module, version = parts[0], parts[1]
        version = version.removesuffix("/go.mod")
        key = (module, version)
        if module and version and key not in seen:
            seen.add(key)
            refs.append(DependencyRef("Go", module, version))
    return refs
