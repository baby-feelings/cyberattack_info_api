"""app.runtimes.status（使っている版の状態の判定）のテスト。"""
from datetime import date

from app.runtimes.models import RuntimeRelease
from app.runtimes.status import cycle_key, evaluate, recommended_release

TODAY = date(2026, 10, 27)


def _rel(runtime, cycle, latest, *, eol=None, is_eol=False, lts=False):
    return RuntimeRelease(
        runtime=runtime, cycle=cycle, latest_version=latest, eol_date=eol,
        is_eol=is_eol, is_lts=lts,
    )


PYTHON_RELEASES = [
    _rel("python", "3.15", "3.15.2", eol=date(2031, 10, 31)),
    _rel("python", "3.13", "3.13.17", eol=date(2029, 10, 31)),
    _rel("python", "3.11", "3.11.16", eol=date(2027, 10, 31)),
    _rel("python", "3.10", "3.10.20", eol=date(2026, 10, 1), is_eol=True),
]
NODE_RELEASES = [
    _rel("nodejs", "25", "25.1.0", eol=date(2026, 6, 1), is_eol=True),
    _rel("nodejs", "24", "24.22.1", eol=date(2028, 4, 30), lts=True),
    _rel("nodejs", "22", "22.17.1", eol=date(2027, 4, 30), lts=True),
]


class TestCycleKey:
    def test_orders_numerically_not_lexically(self):
        assert cycle_key("3.9") < cycle_key("3.13")
        assert cycle_key("22") < cycle_key("24")

    def test_unparseable_sorts_first(self):
        assert cycle_key("x") == (0,)


class TestRecommendedRelease:
    def test_python_is_latest_maintained(self):
        assert recommended_release("python", PYTHON_RELEASES).cycle == "3.15"

    def test_nodejs_is_latest_lts_not_odd_release(self):
        # 25 はサポート終了済みで LTS でもない。24 が推奨
        assert recommended_release("nodejs", NODE_RELEASES).cycle == "24"

    def test_none_without_releases(self):
        assert recommended_release("python", []) is None


class TestEvaluate:
    def test_eol_when_flagged(self):
        st = evaluate("python", "3.10", pinned=True, releases=PYTHON_RELEASES, today=TODAY)
        assert st.state == "eol"
        assert st.eol_date == date(2026, 10, 1)
        assert st.days_to_eol == -26

    def test_eol_when_date_has_passed_even_if_not_flagged(self):
        rels = [_rel("python", "3.9", "3.9.9", eol=date(2025, 10, 31), is_eol=False)]
        assert evaluate("python", "3.9", pinned=True, releases=rels, today=TODAY).state == "eol"

    def test_eol_soon_within_window(self):
        # 3.11 のサポート終了は 2027-10-31（約 1 年後）で、まだ期限間近ではない
        assert evaluate(
            "python", "3.11", pinned=True, releases=PYTHON_RELEASES, today=TODAY,
        ).state == "update_available"
        assert evaluate(
            "python", "3.11", pinned=True, releases=PYTHON_RELEASES, today=date(2027, 6, 1),
        ).state == "eol_soon"

    def test_node22_becomes_eol_soon_as_deadline_approaches(self):
        far = evaluate("nodejs", "22", pinned=True, releases=NODE_RELEASES, today=TODAY)
        near = evaluate("nodejs", "22", pinned=True, releases=NODE_RELEASES,
                        today=date(2026, 11, 5))
        assert far.state == "update_available"
        assert near.state == "eol_soon"
        assert near.days_to_eol == 176

    def test_update_available_when_newer_cycle_exists(self):
        st = evaluate("python", "3.13", pinned=True, releases=PYTHON_RELEASES, today=TODAY)
        assert st.state == "update_available"
        assert st.latest_version == "3.13.17"
        assert (st.recommended_cycle, st.recommended_version) == ("3.15", "3.15.2")

    def test_latest_when_on_recommended_cycle(self):
        st = evaluate("nodejs", "24", pinned=True, releases=NODE_RELEASES, today=TODAY)
        assert st.state == "latest"

    def test_reference_when_not_pinned(self):
        # 下限の指定は、期限切れの版でも警告にしない
        st = evaluate("python", "3.10", pinned=False, releases=PYTHON_RELEASES, today=TODAY)
        assert st.state == "reference"

    def test_unknown_when_cycle_not_in_releases(self):
        st = evaluate("python", "3.99", pinned=True, releases=PYTHON_RELEASES, today=TODAY)
        assert st.state == "unknown"
        assert st.latest_version is None

    def test_runtimes_are_evaluated_independently(self):
        """他の言語のリリースは、判定に影響しない。"""
        st = evaluate("python", "3.13", pinned=True, releases=NODE_RELEASES, today=TODAY)
        assert st.state == "unknown"
        assert st.recommended_cycle is None

    def test_flutter_has_no_eol(self):
        rels = [_rel("flutter", "3.47", "3.47.8"), _rel("flutter", "3.40", "3.40.2")]
        old = evaluate("flutter", "3.40", pinned=True, releases=rels, today=TODAY)
        new = evaluate("flutter", "3.47", pinned=True, releases=rels, today=TODAY)
        assert (old.state, old.eol_date, old.days_to_eol) == ("update_available", None, None)
        assert new.state == "latest"
