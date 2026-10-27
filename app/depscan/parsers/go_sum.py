"""go.sum（Go）パーサー。

各行は "module version hash" または "module version/go.mod hash" の形式。
同一 module/version の重複行（本体 + go.mod）は1件に統合する。
"""
from app.depscan.parsers.base import DependencyRef

# 1行に最低限必要な項目数（モジュール名・バージョン。3つ目はハッシュ）
_MIN_FIELDS = 2


def parse_go_sum(content: str) -> list[DependencyRef]:
    seen: set[tuple[str, str]] = set()
    refs: list[DependencyRef] = []
    for line in content.splitlines():
        parts = line.split()
        if len(parts) < _MIN_FIELDS:
            continue
        module, version = parts[0], parts[1]
        version = version.removesuffix("/go.mod")
        key = (module, version)
        if module and version and key not in seen:
            seen.add(key)
            refs.append(DependencyRef("Go", module, version))
    return refs
