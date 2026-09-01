"""Gemfile.lock（RubyGems）パーサー。

"GEM" セクションの "specs:" 直下（4スペースインデント）のみを対象とする。
それより深いインデント（依存関係の制約表記、例: "      actionpack (= 7.0.4)"）は除外する。
"""
import re

from app.dependency_parsers.base import DependencyRef

_SPEC_LINE_RE = re.compile(r"^ {4}([A-Za-z0-9_.\-]+) \(([\d][\w.\-]*)\)\s*$")


def parse_gemfile_lock(content: str) -> list[DependencyRef]:
    refs: list[DependencyRef] = []
    for line in content.splitlines():
        match = _SPEC_LINE_RE.match(line)
        if match:
            refs.append(DependencyRef("RubyGems", match.group(1), match.group(2)))
    return refs
