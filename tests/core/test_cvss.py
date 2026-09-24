"""app.core.cvss（CVSS 3.1 基本値計算）のテスト。

NVD が公開している既知のベクター例とスコアの組み合わせで、計算式の正確性を検証する。
参照値は CVSS 3.1 仕様書・NVD の CVSS v3 計算機で広く用いられる例。
"""
import pytest

from app.core.cvss import calculate_base_score, parse_vector


class TestParseVector:
    def test_parses_all_metrics(self):
        result = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert result == {
            "AV": "N", "AC": "L", "PR": "N", "UI": "N",
            "S": "U", "C": "H", "I": "H", "A": "H",
        }

    def test_invalid_vector_raises(self):
        with pytest.raises(ValueError):
            parse_vector("not-a-vector")

    def test_incomplete_vector_raises(self):
        with pytest.raises(ValueError):
            parse_vector("CVSS:3.1/AV:N/AC:L")


class TestCalculateBaseScore:
    def test_critical_network_full_impact(self):
        """AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H は CVSS 3.1 の代表的な Critical 例（9.8）。"""
        score = calculate_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        assert score == 9.8

    def test_scope_changed_maximizes_to_10(self):
        """AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H はスコア上限の10.0になる代表例。"""
        score = calculate_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        assert score == 10.0

    def test_low_severity_example(self):
        """AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N は Low〜Medium帯域の代表例。"""
        score = calculate_base_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N")
        assert score == 3.7

    def test_no_impact_yields_zero(self):
        """C/I/A すべて None なら影響サブスコアが0になり、基本値も0.0になる。"""
        score = calculate_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
        assert score == 0.0

    def test_local_privileged_example(self):
        """AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H はローカル権限昇格の代表例（6.7近辺）。"""
        score = calculate_base_score("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")
        assert score == 6.7

    def test_score_within_valid_range(self):
        score = calculate_base_score("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")
        assert 0.0 <= score <= 10.0

    def test_invalid_vector_raises(self):
        with pytest.raises(ValueError):
            calculate_base_score("CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C")
