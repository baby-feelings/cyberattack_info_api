"""app.core.finding_format（検知の共通整形）の、悪意あるパッケージ（OSV `MAL-*`）まわりのテスト。"""
from app.core.finding_format import (
    MALICIOUS_RESPONSE_STEPS,
    format_malicious_section,
    format_package_lines,
    is_malicious_finding,
    split_malicious,
)


def _finding(**kwargs):
    base = {
        "repo_full_name": "u/r",
        "package_name": "evil-pkg",
        "installed_version": "1.0.0",
        "severity": "CRITICAL",
        "fixed_versions": [],
        "osv_id": "MAL-2026-1234",
    }
    base.update(kwargs)
    return base


class TestIsMaliciousFinding:
    def test_true_for_mal_prefixed_osv_id(self):
        assert is_malicious_finding(_finding()) is True

    def test_false_for_ordinary_advisories(self):
        assert is_malicious_finding(_finding(osv_id="GHSA-xxxx-xxxx-xxxx")) is False
        assert is_malicious_finding(_finding(osv_id="PYSEC-2026-1")) is False

    def test_false_when_osv_id_is_missing_or_none(self):
        assert is_malicious_finding({"package_name": "p"}) is False
        assert is_malicious_finding(_finding(osv_id=None)) is False


class TestSplitMalicious:
    def test_splits_into_malicious_and_others_keeping_order(self):
        a = _finding(osv_id="GHSA-a")
        b = _finding(osv_id="MAL-1")
        c = _finding(osv_id="CVE-2026-1")
        d = _finding(osv_id="MAL-2")

        malicious, others = split_malicious([a, b, c, d])

        assert malicious == [b, d]
        assert others == [a, c]

    def test_empty(self):
        assert split_malicious([]) == ([], [])


class TestFormatPackageLines:
    def test_marks_malicious_packages_so_they_are_not_read_as_fixable(self):
        lines = format_package_lines([_finding()])

        assert len(lines) == 1
        assert "🛑 悪意あるパッケージ: evil-pkg 1.0.0" in lines[0]

    def test_does_not_mark_ordinary_advisories(self):
        lines = format_package_lines([_finding(osv_id="GHSA-x", severity="HIGH")])

        assert "悪意あるパッケージ" not in lines[0]


class TestFormatMaliciousSection:
    def test_contains_the_package_and_every_response_step(self):
        text = "\n".join(format_malicious_section([_finding()]))

        assert "evil-pkg 1.0.0" in text
        assert "マルウェア" in text
        for step in MALICIOUS_RESPONSE_STEPS:
            assert step in text

    def test_steps_cover_removal_and_credential_rotation(self):
        steps = "\n".join(MALICIOUS_RESPONSE_STEPS)

        assert "削除" in steps
        assert "再発行" in steps
