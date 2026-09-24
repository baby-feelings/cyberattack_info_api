"""app.codescan.cvss_mapping（Semgrep検知結果からのCVSSベクター推定）のテスト。"""
from app.codescan.cvss_mapping import estimate_cvss_vector
from app.core.cvss import calculate_base_score


class TestEstimateCvssVector:
    def test_known_cwe_hardcoded_credentials_uses_local_av(self):
        """CWE-798（ハードコード認証情報）はソース閲覧が前提のためAV:Lになる。"""
        vector = estimate_cvss_vector("ERROR", ["CWE-798: Use of Hard-coded Credentials"])
        assert "AV:L" in vector

    def test_known_cwe_sql_injection_uses_network_av(self):
        vector = estimate_cvss_vector("ERROR", ["CWE-89: SQL Injection"])
        assert "AV:N" in vector
        assert "C:H" in vector

    def test_known_cwe_command_injection(self):
        vector = estimate_cvss_vector("ERROR", ["CWE-78: OS Command Injection"])
        assert "AV:N" in vector
        assert "A:H" in vector

    def test_known_cwe_xss_requires_user_interaction(self):
        vector = estimate_cvss_vector("WARNING", ["CWE-79: Cross-site Scripting"])
        assert "UI:R" in vector

    def test_known_cwe_insecure_crypto(self):
        vector = estimate_cvss_vector("WARNING", ["CWE-327: Use of a Broken Crypto Algorithm"])
        assert "C:H" in vector

    def test_known_cwe_weak_crypto_key(self):
        vector = estimate_cvss_vector("WARNING", ["CWE-326: Inadequate Encryption Strength"])
        assert "C:H" in vector

    def test_known_cwe_path_traversal(self):
        vector = estimate_cvss_vector("ERROR", ["CWE-22: Path Traversal"])
        assert "AV:N" in vector

    def test_unknown_cwe_falls_back_to_severity_error(self):
        vector = estimate_cvss_vector("ERROR", ["CWE-9999: Unknown Category"])
        assert vector == estimate_cvss_vector("ERROR", None)

    def test_no_cwe_falls_back_to_severity_warning(self):
        vector = estimate_cvss_vector("WARNING", None)
        assert "C:L" in vector

    def test_no_cwe_falls_back_to_severity_info(self):
        vector = estimate_cvss_vector("INFO", [])
        assert "AC:H" in vector

    def test_unknown_severity_falls_back_to_default(self):
        vector = estimate_cvss_vector("UNKNOWN_SEVERITY", None)
        assert vector == estimate_cvss_vector("WARNING", None)

    def test_severity_is_case_insensitive(self):
        assert estimate_cvss_vector("error", None) == estimate_cvss_vector("ERROR", None)

    def test_first_matching_cwe_wins_when_multiple(self):
        vector = estimate_cvss_vector("ERROR", ["CWE-79: XSS", "CWE-89: SQL Injection"])
        assert "UI:R" in vector  # CWE-79 (先頭一致) が優先される

    def test_all_fallback_and_mapped_vectors_are_valid_cvss(self):
        """すべての推定結果が app.core.cvss.calculate_base_score で計算可能であることを確認する。"""
        severities = ["ERROR", "WARNING", "INFO"]
        cwe_samples = [
            None, [], ["CWE-798: x"], ["CWE-89: x"], ["CWE-78: x"],
            ["CWE-79: x"], ["CWE-327: x"], ["CWE-326: x"], ["CWE-22: x"],
            ["CWE-99999: unknown"],
        ]
        for severity in severities:
            for cwe_list in cwe_samples:
                vector = estimate_cvss_vector(severity, cwe_list)
                score = calculate_base_score(vector)
                assert 0.0 <= score <= 10.0
