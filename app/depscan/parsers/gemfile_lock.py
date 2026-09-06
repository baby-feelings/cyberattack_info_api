"""Gemfile.lock（RubyGems）パーサー。

"GEM" セクションの "specs:" 直下（4スペースインデント）のみを対象とする。
それより深いインデント（依存関係の制約表記、例: "      actionpack (= 7.0.4)"）は除外する。

nokogiri 等のネイティブ拡張gemは "name (version-platform)"（例: "nokogiri
(1.19.4-aarch64-linux-gnu)"）とプラットフォーム識別子付きで記録される。バージョン
文字列自体にハイフンは含まれない（RubyGems の慣習）ため、末尾の "-platform" 部分は
バージョン比較に含めず切り捨てる。含めたまま OSV に問い合わせると、実際には修正済み
バージョンであっても「未知のプリリリース版」的に扱われ偽陽性を生む（実際に発生した
バグ: 修正済みバージョンと同一の "1.19.4" を使っているのに "1.19.4-aarch64-linux-gnu"
のまま照合し、8件の脆弱性が誤検知された）。
"""
import re

from app.depscan.parsers.base import DependencyRef

_SPEC_LINE_RE = re.compile(r"^ {4}([A-Za-z0-9_.\-]+) \(([\d][\w.]*)(?:-[\w.\-]+)?\)\s*$")


def parse_gemfile_lock(content: str) -> list[DependencyRef]:
    refs: list[DependencyRef] = []
    for line in content.splitlines():
        match = _SPEC_LINE_RE.match(line)
        if match:
            refs.append(DependencyRef("RubyGems", match.group(1), match.group(2)))
    return refs
