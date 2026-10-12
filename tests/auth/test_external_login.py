"""auth.external_login（GitHub ログインの戻りを別の機能へ任せる登録口）のテスト。"""
from unittest.mock import MagicMock

import pytest

from app.auth import external_login
from app.auth.external_login import ExternalLoginFlow


@pytest.fixture(autouse=True)
def _isolated_registry(monkeypatch):
    """他のテストが登録した流れの影響を受けない（テスト終了後に元へ戻る）。"""
    monkeypatch.setattr(external_login, "_flows", {})


def _flow(name: str, prefix: str) -> ExternalLoginFlow:
    return ExternalLoginFlow(
        name=name,
        decode_state=lambda s: s.removeprefix(prefix) if s.startswith(prefix) else None,
        complete=MagicMock(),
    )


def test_find_returns_none_when_nothing_is_registered():
    assert external_login.find("any-state") is None


def test_find_returns_the_matching_flow_and_its_identifier():
    a, b = _flow("a", "a:"), _flow("b", "b:")
    external_login.register(a)
    external_login.register(b)
    assert external_login.find("b:123") == (b, "123")
    assert external_login.find("a:456") == (a, "456")


def test_find_returns_none_when_no_flow_claims_the_state():
    external_login.register(_flow("a", "a:"))
    assert external_login.find("dashboard-random-state") is None


def test_registering_the_same_name_replaces_the_flow():
    first, second = _flow("a", "x:"), _flow("a", "y:")
    external_login.register(first)
    external_login.register(second)
    assert external_login.find("x:1") is None  # 置き換わったので前の流れは残らない
    assert external_login.find("y:1") == (second, "1")
