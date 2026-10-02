"""app.core.registry_client（パッケージレジストリの最新バージョン取得）のユニットテスト。

DEPSCAN が「OSV に last_affected しか無い脆弱性」の修正版を補うために使う。
取得失敗は例外にせず None を返す（ベストエフォート）ことと、版の大小比較が
数値のみの表記に限って行われることを検証する。
"""
from unittest.mock import MagicMock, patch

import httpx
import pytest

from app.core.registry_client import fetch_latest_version, is_newer_version


def _mock_client(json_body=None, error: Exception | None = None) -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = json_body
    if error is not None:
        resp.raise_for_status.side_effect = error
    client = MagicMock()
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.get.return_value = resp
    return client


def _fetch(ecosystem: str, name: str, body) -> tuple[str | None, MagicMock]:
    client = _mock_client(body)
    with patch("app.core.registry_client.httpx.Client", return_value=client):
        return fetch_latest_version(ecosystem, name), client


class TestIsNewerVersion:
    @pytest.mark.parametrize(("candidate", "baseline", "expected"), [
        ("1.15.0", "1.14.0", True),
        ("1.14.1", "1.14.0", True),
        ("2.0.0", "1.99.99", True),
        ("1.10.0", "1.9.0", True),   # 文字列比較なら誤判定する桁上がり
        ("1.14.0", "1.14.0", False),
        ("1.13.9", "1.14.0", False),
        ("1.2", "1.2.0", False),     # 桁数違いは同一視
        ("1.2.1", "1.2", True),
    ])
    def test_numeric_versions(self, candidate, baseline, expected):
        assert is_newer_version(candidate, baseline) is expected

    @pytest.mark.parametrize(("candidate", "baseline"), [
        ("2.0.0rc1", "1.0.0"),       # プレリリースは大小に確信が持てない
        ("2.0.0", "1.0.0-beta.1"),
        ("2.0.0+build5", "1.0.0"),
        ("latest", "1.0.0"),
        ("", "1.0.0"),
    ])
    def test_non_numeric_versions_are_never_newer(self, candidate, baseline):
        assert is_newer_version(candidate, baseline) is False


class TestFetchLatestVersion:
    def test_pypi(self):
        latest, client = _fetch("PyPI", "accelerate", {"info": {"version": "1.15.0"}})
        assert latest == "1.15.0"
        assert client.get.call_args.args[0] == "https://pypi.org/pypi/accelerate/json"

    def test_npm(self):
        latest, client = _fetch("npm", "brace-expansion", {"version": "2.1.7"})
        assert latest == "2.1.7"
        assert client.get.call_args.args[0] == "https://registry.npmjs.org/brace-expansion/latest"

    def test_npm_scoped_package_encodes_only_the_slash(self):
        _, client = _fetch("npm", "@grpc/grpc-js", {"version": "1.14.5"})
        assert client.get.call_args.args[0] == "https://registry.npmjs.org/@grpc%2Fgrpc-js/latest"

    def test_rubygems(self):
        latest, client = _fetch("RubyGems", "rubyzip", {"version": "3.4.0"})
        assert latest == "3.4.0"
        assert client.get.call_args.args[0] == "https://rubygems.org/api/v1/gems/rubyzip.json"

    def test_crates_io(self):
        latest, _ = _fetch("crates.io", "serde", {"crate": {"max_stable_version": "1.0.230"}})
        assert latest == "1.0.230"

    def test_pub(self):
        latest, _ = _fetch("Pub", "http", {"latest": {"version": "1.6.0"}})
        assert latest == "1.6.0"

    def test_unsupported_ecosystem_returns_none_without_request(self):
        with patch("app.core.registry_client.httpx.Client") as client_cls:
            assert fetch_latest_version("Maven", "com.example:lib") is None
        client_cls.assert_not_called()

    def test_http_error_returns_none(self):
        error = httpx.HTTPStatusError(
            "404", request=MagicMock(), response=MagicMock(status_code=404, headers={}),
        )
        with patch("app.core.registry_client.httpx.Client", return_value=_mock_client(error=error)):
            assert fetch_latest_version("PyPI", "no-such-package") is None

    def test_connection_error_returns_none(self):
        client = _mock_client()
        client.get.side_effect = httpx.ConnectError("down")
        with patch("app.core.registry_client.httpx.Client", return_value=client), \
                patch("app.core.retry.time.sleep"):
            assert fetch_latest_version("PyPI", "pkg") is None

    @pytest.mark.parametrize("body", [{}, {"info": {}}, None, {"info": {"version": None}},
                                      {"info": {"version": ""}}, {"info": {"version": 1}}])
    def test_unexpected_response_shape_returns_none(self, body):
        latest, _ = _fetch("PyPI", "pkg", body)
        assert latest is None
