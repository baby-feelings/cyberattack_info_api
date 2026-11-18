"""ダッシュボードの特定のタブ・小タブへ直接開くリンクのテスト。"""
from urllib.parse import parse_qs, urlparse

from app.core.notifications.dashboard_links import (
    CODE_SCAN,
    DEPS_SLA,
    OPS_SITES,
    DashboardTarget,
    crawler_link,
)
from app.core.notifications.slack import DASHBOARD_URL


def _query(url: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(url).query)


def test_url_has_tab_and_sub() -> None:
    url = DEPS_SLA.url()
    assert url.startswith(DASHBOARD_URL + "?")
    assert _query(url) == {"tab": ["dependencies"], "sub": ["sla"]}


def test_url_without_sub_omits_it() -> None:
    assert _query(OPS_SITES.url()) == {"tab": ["ops"]}


def test_custom_base() -> None:
    assert DashboardTarget("code", "scan").url("https://x.example/") == "https://x.example/?tab=code&sub=scan"


def test_crawler_link_known_and_unknown() -> None:
    assert crawler_link("CODESCAN") == CODE_SCAN.url()
    assert _query(crawler_link("KEV")) == {"tab": ["public"], "sub": ["kev"]}
    # 対応するタブが無い種別は、トップ
    assert crawler_link("COMMITWATCH") == DASHBOARD_URL
