"""app.runtimes.eol_client（最新版・サポート期限の取得）のテスト。"""
from datetime import date
from unittest.mock import patch

import httpx
import pytest

from app.runtimes import eol_client
from app.runtimes.eol_client import (
    fetch_all_releases,
    fetch_endoflife,
    fetch_flutter_and_dart,
)

_ENDOFLIFE_PYTHON = {"result": {"releases": [
    {"name": "3.15", "releaseDate": "2026-10-09", "isEol": False, "eolFrom": "2031-10-31",
     "isLts": False, "latest": {"name": "3.15.2"}},
    {"name": "3.10", "releaseDate": "2021-10-04", "isEol": True, "eolFrom": "2026-10-01",
     "isLts": False, "latest": {"name": "3.10.20"}},
    {"name": "broken", "latest": None},
]}}

_FLUTTER = {"releases": [
    {"channel": "stable", "version": "3.47.8", "dart_sdk_version": "3.13.7",
     "release_date": "2026-10-23T19:02:25.384067Z"},
    {"channel": "stable", "version": "3.47.7", "dart_sdk_version": "3.13.5",
     "release_date": "2026-10-08T23:42:24Z"},
    {"channel": "beta", "version": "3.48.0-0.1.pre", "dart_sdk_version": "3.14.0",
     "release_date": "2026-10-20T00:00:00Z"},
    {"channel": "stable", "version": "v1.22.6", "dart_sdk_version": "2.10.5",
     "release_date": "2020-10-01T00:00:00Z"},
    {"channel": "stable", "version": "3.40.2", "dart_sdk_version": "3.10.1",
     "release_date": "2026-05-01T00:00:00Z"},
]}


_REAL_CLIENT = httpx.Client  # 差し替え後の `httpx.Client` ではなく、本物のクラスを使うために控える


def _client(handler) -> httpx.Client:
    return _REAL_CLIENT(transport=httpx.MockTransport(handler))


def _patched_client(handler):
    """`fetch_all_releases` が作る `httpx.Client` を、モック転送のものに差し替える。"""
    return patch.object(
        eol_client.httpx, "Client",
        lambda **kwargs: _REAL_CLIENT(transport=httpx.MockTransport(handler)),
    )


class TestFetchEndoflife:
    def test_parses_releases_and_skips_incomplete_ones(self):
        client = _client(lambda request: httpx.Response(200, json=_ENDOFLIFE_PYTHON))
        infos = fetch_endoflife("python", client)

        assert [i.cycle for i in infos] == ["3.15", "3.10"]
        first = infos[0]
        assert first.runtime == "python"
        assert first.latest_version == "3.15.2"
        assert first.release_date == date(2026, 10, 9)
        assert first.eol_date == date(2031, 10, 31)
        assert (first.is_eol, first.is_lts) == (False, False)
        assert infos[1].is_eol is True

    def test_requests_the_product_endpoint(self):
        seen = []

        def handler(request):
            seen.append(str(request.url))
            return httpx.Response(200, json={"result": {"releases": []}})

        fetch_endoflife("nodejs", _client(handler))
        assert seen == ["https://endoflife.date/api/v1/products/nodejs/"]

    def test_http_error_raises(self):
        client = _client(lambda request: httpx.Response(500))
        with pytest.raises(httpx.HTTPStatusError):
            fetch_endoflife("python", client)


class TestParseDate:
    def test_reads_date_prefix_and_rejects_the_rest(self):
        assert eol_client._parse_date("2026-10-23T19:02:25Z") == date(2026, 10, 23)
        assert eol_client._parse_date(None) is None
        assert eol_client._parse_date("soon") is None
        assert eol_client._parse_date("2026-13-45") is None


class TestFetchFlutterAndDart:
    def test_aggregates_latest_per_cycle_for_stable_only(self):
        client = _client(lambda request: httpx.Response(200, json=_FLUTTER))
        infos = fetch_flutter_and_dart(client)
        by_key = {(i.runtime, i.cycle): i for i in infos}

        # 同じ系列の複数リリースは、最新の版にまとめる
        assert by_key[("flutter", "3.47")].latest_version == "3.47.8"
        # 公開日は、系列の最初のリリース（3.47.7）の日。最新のパッチ（3.47.8）の日ではない
        assert by_key[("flutter", "3.47")].release_date == date(2026, 10, 8)
        assert by_key[("dart", "3.13")].latest_version == "3.13.7"
        # beta・古い 1.x/2.x は含めない
        assert ("flutter", "3.48") not in by_key
        assert not any(k[1].startswith(("1.", "2.")) for k in by_key)
        assert ("flutter", "3.40") in by_key and ("dart", "3.10") in by_key
        # サポート期限は定められていない
        assert all(i.eol_date is None and not i.is_eol for i in infos)


class TestFetchAllReleases:
    def test_partial_failure_returns_what_was_fetched(self):
        def handler(request):
            if "nodejs" in str(request.url):
                return httpx.Response(503)
            if "endoflife.date" in str(request.url):
                return httpx.Response(200, json=_ENDOFLIFE_PYTHON)
            return httpx.Response(200, json=_FLUTTER)

        with _patched_client(handler):
            infos = fetch_all_releases()

        runtimes = {i.runtime for i in infos}
        assert runtimes == {"python", "flutter", "dart"}

    def test_all_failures_raise(self):
        with (
            _patched_client(lambda request: httpx.Response(500)),
            pytest.raises(httpx.HTTPStatusError),
        ):
            fetch_all_releases()
