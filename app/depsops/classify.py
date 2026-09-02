"""Dependabot PR タイトルからバージョンアップの種別を判定するモジュール。

自動マージ可否の判断材料にするため、タイトル中の「from X to Y」パターンを
正規表現で抽出し、メジャーバージョンが変わっているかを判定する。
"""
import re
from typing import Literal

BumpKind = Literal["major", "minor_or_patch", "unknown"]

_FROM_TO_RE = re.compile(r"from\s+(\S+)\s+to\s+(\S+)", re.IGNORECASE)
_MAJOR_MINOR_RE = re.compile(r"(\d+)\.(\d+)")


def _major_minor(version: str) -> tuple[int, int] | None:
    """バージョン文字列（`>=1.2.3` 等の前置演算子含む）から (major, minor) を抽出する。"""
    match = _MAJOR_MINOR_RE.search(version)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def classify_bump(pr_title: str) -> BumpKind:
    """Dependabot PR タイトルからバージョンアップ種別を判定する。

    - "major": メジャーバージョンが変わる（0.x系は minor の変化も major 扱い。
      semver の慣習で 0.x は minor が実質的な破壊的変更を意味するため）
    - "minor_or_patch": メジャーバージョンが変わらない
    - "unknown": タイトルから "from X to Y" 形式のバージョンが抽出できない
      （複数パッケージをまとめた grouped PR 等）。安全側に倒し major 同様に扱う
    """
    match = _FROM_TO_RE.search(pr_title)
    if not match:
        return "unknown"

    from_v = _major_minor(match.group(1))
    to_v = _major_minor(match.group(2))
    if from_v is None or to_v is None:
        return "unknown"

    from_major, from_minor = from_v
    to_major, to_minor = to_v

    if from_major != to_major:
        return "major"
    if from_major == 0 and from_minor != to_minor:
        return "major"
    return "minor_or_patch"
