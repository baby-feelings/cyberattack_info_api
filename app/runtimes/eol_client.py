"""言語・実行環境の最新版とサポート期限の取得（RUNTIME）。

取得元は2つ。

- Python・Node.js: endoflife.date の公開 API（系列ごとの最新版・サポート終了日・LTS）
- Flutter・Dart: Flutter 公式のリリース情報（`releases_linux.json`）。Flutter・Dart には
  サポート終了日が定められていないため、系列ごとの最新版と公開日だけを取る。Dart の版は、
  Flutter の各リリースに同梱される Dart SDK の版から求める
"""
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date

import httpx

from app.runtimes.detector import DART, FLUTTER, NODEJS, PYTHON

logger = logging.getLogger(__name__)

_TIMEOUT = 30.0
_ENDOFLIFE_URL = "https://endoflife.date/api/v1/products/{product}/"
_FLUTTER_RELEASES_URL = (
    "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json"
)

# 識別子 → endoflife.date の製品名
_ENDOFLIFE_PRODUCTS = {PYTHON: "python", NODEJS: "nodejs"}

# 古すぎる系列（Flutter・Dart の 1.x・2.x）は、使っているかの判定に不要なため保存しない
_MIN_MAJOR = 3

_VERSION_RE = re.compile(r"v?(\d{1,4})\.(\d{1,4})\.(\d{1,4})")


@dataclass(frozen=True)
class ReleaseInfo:
    """バージョン系列1つ分の、最新版とサポート期限。"""

    runtime: str
    cycle: str
    latest_version: str
    release_date: date | None
    eol_date: date | None
    is_eol: bool
    is_lts: bool


def _parse_date(value: object) -> date | None:
    """`2026-10-09` や `2026-10-23T19:02:25Z` の先頭10文字を日付にする。読めなければ None。"""
    if not isinstance(value, str) or len(value) < 10:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def fetch_endoflife(runtime: str, client: httpx.Client) -> list[ReleaseInfo]:
    """endoflife.date から、Python または Node.js の系列ごとの最新版・サポート期限を取得する。"""
    product = _ENDOFLIFE_PRODUCTS[runtime]
    resp = client.get(_ENDOFLIFE_URL.format(product=product))
    resp.raise_for_status()
    releases = resp.json().get("result", {}).get("releases", [])
    infos = []
    for item in releases:
        cycle, latest = item.get("name"), (item.get("latest") or {}).get("name")
        if not cycle or not latest:
            continue
        infos.append(ReleaseInfo(
            runtime=runtime,
            cycle=str(cycle),
            latest_version=str(latest),
            release_date=_parse_date(item.get("releaseDate")),
            eol_date=_parse_date(item.get("eolFrom")),
            is_eol=bool(item.get("isEol")),
            is_lts=bool(item.get("isLts")),
        ))
    return infos


def fetch_flutter_and_dart(client: httpx.Client) -> list[ReleaseInfo]:
    """Flutter 公式のリリース情報から、Flutter・Dart の系列ごとの最新版を求める（stable のみ）。"""
    resp = client.get(_FLUTTER_RELEASES_URL)
    resp.raise_for_status()
    # 系列 → (最新版のタプル, 最新版の文字列, 公開日)
    latest: dict[tuple[str, str], tuple[tuple[int, int, int], str, date | None]] = {}
    for release in resp.json().get("releases", []):
        if release.get("channel") != "stable":
            continue
        released = _parse_date(release.get("release_date"))
        for runtime, version in (
            (FLUTTER, release.get("version")), (DART, release.get("dart_sdk_version")),
        ):
            match = _VERSION_RE.match(str(version or ""))
            if not match or int(match.group(1)) < _MIN_MAJOR:
                continue
            numbers = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
            key = (runtime, f"{numbers[0]}.{numbers[1]}")
            current = latest.get(key)
            if current is None or numbers > current[0]:
                latest[key] = (numbers, ".".join(map(str, numbers)), released)
    return [
        ReleaseInfo(
            runtime=runtime, cycle=cycle, latest_version=version, release_date=released,
            eol_date=None, is_eol=False, is_lts=False,
        )
        for (runtime, cycle), (_, version, released) in sorted(latest.items())
    ]


def fetch_all_releases() -> list[ReleaseInfo]:
    """全ての言語・実行環境の最新版・サポート期限を取得する。

    取得元ごとに失敗を切り分け、一部が失敗しても、取れたものは返す（失敗した分は、
    DB に前回までの内容が残る）。全て失敗した場合は、最後の例外を送出する。
    """
    infos: list[ReleaseInfo] = []
    last_error: Exception | None = None
    with httpx.Client(timeout=_TIMEOUT, follow_redirects=True) as client:
        sources: list[tuple[str, Callable[[], list[ReleaseInfo]]]] = [
            ("endoflife.date python", lambda: fetch_endoflife(PYTHON, client)),
            ("endoflife.date nodejs", lambda: fetch_endoflife(NODEJS, client)),
            ("Flutter releases", lambda: fetch_flutter_and_dart(client)),
        ]
        for name, fetch in sources:
            try:
                infos.extend(fetch())
            except (httpx.HTTPError, ValueError) as exc:
                logger.error("RUNTIME: failed to fetch %s: %s", name, exc)
                last_error = exc
    if not infos and last_error is not None:
        raise last_error
    return infos
