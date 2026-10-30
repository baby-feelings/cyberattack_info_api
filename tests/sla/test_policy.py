"""app.sla.policy（重要度・KEV から対応期限を決める方針）のテスト。"""
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.sla.policy import SlaPolicy

POLICY = SlaPolicy(critical_days=7, high_days=30, medium_days=90, kev_days=7)


class TestDaysForSeverity:
    @pytest.mark.parametrize(
        ("severity", "expected"),
        [("CRITICAL", 7), ("HIGH", 30), ("MEDIUM", 90), ("critical", 7)],
    )
    def test_severities_with_a_deadline(self, severity, expected):
        assert POLICY.days_for_severity(severity) == expected

    @pytest.mark.parametrize("severity", ["LOW", "N/A", "", None, "UNKNOWN"])
    def test_low_and_unknown_have_no_deadline(self, severity):
        assert POLICY.days_for_severity(severity) is None


class TestDeadlineDays:
    def test_without_kev_uses_the_severity_deadline(self):
        assert POLICY.deadline_days("HIGH") == 30

    def test_kev_shortens_a_longer_deadline(self):
        assert POLICY.deadline_days("MEDIUM", is_kev=True) == 7
        assert POLICY.deadline_days("HIGH", is_kev=True) == 7

    def test_kev_never_extends_a_shorter_deadline(self):
        policy = SlaPolicy(critical_days=3, high_days=14, medium_days=60, kev_days=7)
        assert policy.deadline_days("CRITICAL", is_kev=True) == 3

    def test_kev_gives_a_deadline_even_to_low_or_unknown(self):
        assert POLICY.deadline_days("LOW", is_kev=True) == 7
        assert POLICY.deadline_days(None, is_kev=True) == 7

    def test_low_without_kev_has_no_deadline(self):
        assert POLICY.deadline_days("LOW") is None


class TestExclusion:
    def test_is_excluded_matches_listed_osv_ids_only(self):
        policy = SlaPolicy(
            critical_days=7, high_days=30, medium_days=90, kev_days=7,
            excluded_osv_ids=frozenset({"GHSA-aaaa"}),
        )
        assert policy.is_excluded("GHSA-aaaa") is True
        assert policy.is_excluded("GHSA-bbbb") is False


class TestFromSettings:
    def test_defaults(self):
        policy = SlaPolicy.from_settings()

        assert (policy.critical_days, policy.high_days, policy.medium_days) == (7, 30, 90)
        assert policy.kev_days == 7
        assert policy.excluded_osv_ids == frozenset()

    def test_reads_overrides_and_trims_the_exclusion_list(self):
        with patch("app.sla.policy.settings") as mock_settings:
            mock_settings.SLA_CRITICAL_DAYS = 3
            mock_settings.SLA_HIGH_DAYS = 14
            mock_settings.SLA_MEDIUM_DAYS = 60
            mock_settings.SLA_KEV_DAYS = 3
            mock_settings.SLA_EXCLUDE_OSV_IDS = " GHSA-a , ,GHSA-b "
            policy = SlaPolicy.from_settings()

        assert (policy.critical_days, policy.high_days, policy.medium_days) == (3, 14, 60)
        assert policy.excluded_osv_ids == frozenset({"GHSA-a", "GHSA-b"})


class TestSettingsValidation:
    def _settings(self, **overrides):
        return Settings(DATABASE_URL="sqlite://", API_KEY="k", **overrides)  # type: ignore[call-arg]

    def test_rejects_a_deadline_below_one_day(self):
        with pytest.raises(ValidationError):
            self._settings(SLA_CRITICAL_DAYS=0)
        with pytest.raises(ValidationError):
            self._settings(SLA_KEV_DAYS=-1)

    def test_accepts_one_day(self):
        assert self._settings(SLA_HIGH_DAYS=1).SLA_HIGH_DAYS == 1
