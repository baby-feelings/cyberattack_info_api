"""app.core.stix（STIX 2.1変換の共通処理、Issue #134のOSV/JVN拡張）のテスト。"""
from datetime import datetime, timezone

from app.core.stix import STIX_ID_NAMESPACE, stix_timestamp


class TestStixIdNamespace:
    def test_matches_original_kev_namespace_value(self):
        """app.kev.stix._STIX_ID_NAMESPACE から移動した値そのままであることを確認する
        （既存のKEVオブジェクトID生成結果に影響を与えないため、値は変更してはならない）。
        """
        assert str(STIX_ID_NAMESPACE) == "6ba7b810-9dad-11d1-80b4-00c04fd430c8"


class TestStixTimestamp:
    def test_formats_as_rfc3339_with_millis_and_z_suffix(self):
        dt = datetime(2026, 3, 15, 12, 30, 45, 123456, tzinfo=timezone.utc)
        assert stix_timestamp(dt) == "2026-03-15T12:30:45.123Z"

    def test_converts_non_utc_timezone_to_utc(self):
        from datetime import timedelta

        jst = timezone(timedelta(hours=9))
        dt = datetime(2026, 3, 15, 21, 30, 0, tzinfo=jst)
        # JST 21:30 → UTC 12:30
        assert stix_timestamp(dt) == "2026-03-15T12:30:00.000Z"

    def test_truncates_microseconds_to_milliseconds(self):
        dt = datetime(2026, 1, 1, 0, 0, 0, 999_999, tzinfo=timezone.utc)
        assert stix_timestamp(dt) == "2026-01-01T00:00:00.999Z"
