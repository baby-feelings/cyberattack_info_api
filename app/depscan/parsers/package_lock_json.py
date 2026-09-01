"""package-lock.json（npm）パーサー。

npm v7+ の lockfileVersion 2/3 形式（"packages" オブジェクト）に対応する。
"""
import json

from app.depscan.parsers.base import DependencyRef


def parse_package_lock_json(content: str) -> list[DependencyRef]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    refs: list[DependencyRef] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, info in packages.items():
            if not path or not isinstance(info, dict):
                continue
            version = info.get("version")
            if not version:
                continue
            # "node_modules/express" や "node_modules/@scope/name" からパッケージ名を抽出
            idx = path.rfind("node_modules/")
            name = path[idx + len("node_modules/"):] if idx != -1 else path
            if name:
                refs.append(DependencyRef("npm", name, version))
        return refs

    # lockfileVersion 1（"dependencies" ネスト構造）への簡易フォールバック
    dependencies = data.get("dependencies")
    if isinstance(dependencies, dict):
        for name, info in dependencies.items():
            if isinstance(info, dict) and info.get("version"):
                refs.append(DependencyRef("npm", name, info["version"]))

    return refs
