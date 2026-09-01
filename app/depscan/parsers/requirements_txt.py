"""requirements.txt（PyPI）パーサー。

バージョンが厳密に固定されている行（`==`）のみを対象とする。
`>=` 等の範囲指定は実際にインストールされるバージョンを特定できないため対象外。
"""
import re

from app.depscan.parsers.base import DependencyRef

_PIN_RE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-]+)"
)


def parse_requirements_txt(content: str) -> list[DependencyRef]:
    refs: list[DependencyRef] = []
    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        # 環境マーカー（; python_version < "3.11" 等）を除去
        line = line.split(";", 1)[0].strip()
        match = _PIN_RE.match(line)
        if match:
            refs.append(DependencyRef("PyPI", match.group(1), match.group(2)))
    return refs
