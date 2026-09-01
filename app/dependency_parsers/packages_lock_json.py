"""packages.lock.json（NuGet）パーサー。

`dotnet restore --use-lock-file` で生成される形式。
ターゲットフレームワークごとにネストした "dependencies" から解決済みバージョンを抽出する。
"""
import json

from app.dependency_parsers.base import DependencyRef


def parse_packages_lock_json(content: str) -> list[DependencyRef]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    dependencies = data.get("dependencies")
    if not isinstance(dependencies, dict):
        return []

    seen: set[tuple[str, str]] = set()
    refs: list[DependencyRef] = []
    for framework_deps in dependencies.values():
        if not isinstance(framework_deps, dict):
            continue
        for name, info in framework_deps.items():
            if not isinstance(info, dict):
                continue
            resolved = info.get("resolved")
            if not resolved:
                continue
            key = (name, resolved)
            if key not in seen:
                seen.add(key)
                refs.append(DependencyRef("NuGet", name, resolved))
    return refs
