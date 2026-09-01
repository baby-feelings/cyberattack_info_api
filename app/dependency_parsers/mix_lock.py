"""mix.lock（Elixir / Hex）パーサー。

Elixir の term 構文（JSON でも YAML でもない）のため正規表現で抽出する。
例: `"phoenix": {:hex, :phoenix, "1.7.10", "...", [:mix], [...], "hexpm", "..."},`
"""
import re

from app.dependency_parsers.base import DependencyRef

_HEX_ENTRY_RE = re.compile(
    r'"([A-Za-z0-9_]+)":\s*\{:hex,\s*:[A-Za-z0-9_]+,\s*"([\d][\w.\-]*)"'
)


def parse_mix_lock(content: str) -> list[DependencyRef]:
    return [
        DependencyRef("Hex", name, version)
        for name, version in _HEX_ENTRY_RE.findall(content)
    ]
