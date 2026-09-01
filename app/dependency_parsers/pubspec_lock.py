"""pubspec.lock（Dart / Flutter）パーサー。"""
import yaml

from app.dependency_parsers.base import DependencyRef


def parse_pubspec_lock(content: str) -> list[DependencyRef]:
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError:
        return []

    if not isinstance(data, dict):
        return []

    packages = data.get("packages")
    if not isinstance(packages, dict):
        return []

    refs: list[DependencyRef] = []
    for name, info in packages.items():
        if not isinstance(info, dict):
            continue
        version = info.get("version")
        if version:
            refs.append(DependencyRef("Pub", name, str(version)))
    return refs
