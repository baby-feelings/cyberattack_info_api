"""パッケージレジストリ（PyPI・npm 等）の最新バージョン取得（ベストエフォート）。

DEPSCAN は OSV の `fixed` イベントから修正版を取得するが、OSV が影響範囲の上限
（`last_affected`）しか載せていない脆弱性（例: accelerate の PYSEC-2026-3804、
影響範囲は 1.14.0 まで）では修正版が空になり「修正版なし」と誤表示される。
`last_affected` より新しい最新版がレジストリにあればそれは影響を受けないため、
修正版の目安として補えるようにここで最新バージョンを引く。

あくまで補助情報のため、取得失敗（ネットワーク断・未対応エコシステム・想定外の
レスポンス）は例外にせず None を返し、呼び出し側は従来どおり修正版なしとして扱う。
"""
import logging
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import quote

import httpx

from app.core.retry import request_with_retry

logger = logging.getLogger(__name__)

# レジストリ1回あたりのタイムアウト（秒）。補助情報のため短めにする
_TIMEOUT_SECONDS = 15.0

# crates.io は User-Agent が無いリクエストを拒否する
_HEADERS = {"User-Agent": "cyberattack-info-api (DEPSCAN fixed-version inference)"}

# 数値のみの版（1.2.3 形式）。プレリリース・ビルド付きなど大小比較に確信が持てない
# 表記は比較対象外にする（誤って「修正版」と判定するよりは補わない方が安全）
_NUMERIC_VERSION = re.compile(r"^\d+(\.\d+)*$")

# エコシステム別: (URL, レスポンスJSONから最新版を取り出す関数)
_Resolver = Callable[[str], tuple[str, Callable[[dict[str, Any]], Any]]]
_RESOLVERS: dict[str, _Resolver] = {
    "PyPI": lambda name: (
        f"https://pypi.org/pypi/{quote(name, safe='')}/json",
        lambda d: d["info"]["version"],
    ),
    # スコープ付き（@scope/name）はスラッシュのみURLエンコードが必要
    "npm": lambda name: (
        f"https://registry.npmjs.org/{quote(name, safe='@')}/latest",
        lambda d: d["version"],
    ),
    "RubyGems": lambda name: (
        f"https://rubygems.org/api/v1/gems/{quote(name, safe='')}.json",
        lambda d: d["version"],
    ),
    "crates.io": lambda name: (
        f"https://crates.io/api/v1/crates/{quote(name, safe='')}",
        lambda d: d["crate"]["max_stable_version"],
    ),
    "Pub": lambda name: (
        f"https://pub.dev/api/packages/{quote(name, safe='')}",
        lambda d: d["latest"]["version"],
    ),
}


def fetch_latest_version(ecosystem: str, package_name: str) -> str | None:
    """レジストリから最新の安定版バージョンを取得する。取得できなければ None。"""
    resolver = _RESOLVERS.get(ecosystem)
    if resolver is None:
        return None

    url, extract = resolver(package_name)
    try:
        with httpx.Client(timeout=_TIMEOUT_SECONDS, headers=_HEADERS) as client:
            resp = request_with_retry(lambda: client.get(url))
        latest = extract(resp.json())
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        logger.warning(
            "Failed to fetch latest version of %s (%s): %s", package_name, ecosystem, exc,
        )
        return None
    return latest if isinstance(latest, str) and latest else None


def _numeric_tuple(version: str) -> tuple[int, ...] | None:
    if not _NUMERIC_VERSION.match(version):
        return None
    return tuple(int(part) for part in version.split("."))


def is_newer_version(candidate: str, baseline: str) -> bool:
    """candidate が baseline より新しいか。数値のみの版同士でのみ判定し、それ以外は False。"""
    a, b = _numeric_tuple(candidate), _numeric_tuple(baseline)
    if a is None or b is None:
        return False
    # 桁数が違っても比較できるよう 0 埋めする（1.2 と 1.2.0 を同一視）
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) > b + (0,) * (width - len(b))
