"""PR の判定（セキュリティ更新の照合・互換性バッジ・`PrJudge`）のテスト。
"""
import os
from unittest.mock import MagicMock, patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")


from app.core.github.repo import GitHubRepo  # noqa: E402
from app.depsops.pr_judge import (  # noqa: E402
    PrJudge,
    extract_compatibility_badge_url,
    matches_security_alert,
)

TEST_API_KEY = "test-api-key-for-pytest"
HEADERS = {"X-API-KEY": TEST_API_KEY}


def _mock_httpx_client(get_return=None, put_return=None, post_return=None, delete_return=None):
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    if get_return is not None:
        mock_client.get = MagicMock(return_value=get_return)
    if put_return is not None:
        mock_client.put = MagicMock(return_value=put_return)
    if post_return is not None:
        mock_client.post = MagicMock(return_value=post_return)
    if delete_return is not None:
        mock_client.delete = MagicMock(return_value=delete_return)
    return mock_client


def _mock_response(json_data, status_code=200):
    resp = MagicMock()
    resp.status_code = status_code
    resp.raise_for_status = MagicMock()
    resp.json.return_value = json_data
    return resp


# ──────────────────────────────────────────────────────────────
# app.depsops.runner
# ──────────────────────────────────────────────────────────────


class TestMatchesSecurityAlert:
    def test_none_alert_packages_means_unknown(self):
        assert matches_security_alert("Bump requests from 1.0 to 2.0", None) is None

    def test_matching_package_returns_true(self):
        result = matches_security_alert(
            "Bump requests from 1.0 to 2.0", {"requests", "flask"},
        )
        assert result is True

    def test_no_matching_package_returns_false(self):
        result = matches_security_alert(
            "Bump requests from 1.0 to 2.0", {"flask", "django"},
        )
        assert result is False

    def test_empty_alert_set_returns_false(self):
        assert matches_security_alert("Bump requests from 1.0 to 2.0", set()) is False

    def test_matches_case_insensitively(self):
        result = matches_security_alert("Bump REQUESTS from 1.0 to 2.0", {"requests"})
        assert result is True

    def test_does_not_match_substring_of_a_different_package(self):
        """"requests" は "requests_toolbelt" の一部として誤マッチしないこと。"""
        result = matches_security_alert(
            "Bump requests_toolbelt from 1.0 to 2.0", {"requests"},
        )
        assert result is False


class TestExtractCompatibilityBadgeUrl:
    def test_extracts_badge_url_from_pr_body(self):
        body = (
            "Bumps google-genai from 2.19.0 to 2.20.0.\n\n"
            "[![Dependabot compatibility score]"
            "(https://dependabot-badges.githubapp.com/badges/compatibility_score"
            "?dependency-name=google-genai&package-manager=pip"
            "&previous-version=2.19.0&new-version=2.20.0)]"
            "(https://docs.github.com/en/github/managing-security-vulnerabilities/"
            "about-dependabot-security-updates#about-compatibility-scores)"
        )
        url = extract_compatibility_badge_url(body)
        assert url == (
            "https://dependabot-badges.githubapp.com/badges/compatibility_score"
            "?dependency-name=google-genai&package-manager=pip"
            "&previous-version=2.19.0&new-version=2.20.0"
        )

    def test_returns_none_when_badge_absent(self):
        """範囲指定の requirement 更新PR等、バッジが埋め込まれないケース。"""
        body = "Updates the requirements on foo to permit the latest version."
        assert extract_compatibility_badge_url(body) is None

    def test_returns_none_for_empty_body(self):
        assert extract_compatibility_badge_url(None) is None
        assert extract_compatibility_badge_url("") is None


class TestProcessPr:
    def _pr(self, title="Bump x from 1.0.0 to 1.0.1", number=1):
        return {"number": number, "title": title}

    def test_dirty_requests_rebase(self):
        with patch(
            "app.depsops.pr_judge.get_pull_request", return_value={"mergeable_state": "dirty"},
        ), patch("app.depsops.pr_judge.request_rebase") as mock_rebase, \
           patch("app.depsops.pr_judge.merge_pull_request") as mock_merge:
            action, item = PrJudge(GitHubRepo("u", "r", "token"), has_ci=True).judge(self._pr())
        assert action == "flagged"
        assert "リベース" in item["reason"]
        mock_rebase.assert_called_once()
        mock_merge.assert_not_called()

    def test_no_ci_flags_without_merging(self):
        with patch(
            "app.depsops.pr_judge.get_pull_request", return_value={"mergeable_state": "clean"},
        ), patch("app.depsops.pr_judge.merge_pull_request") as mock_merge:
            action, item = PrJudge(GitHubRepo("u", "r", "token"), has_ci=False).judge(self._pr())
        assert action == "flagged"
        assert "CI未設定" in item["reason"]
        mock_merge.assert_not_called()

    def test_major_bump_flags_without_merging(self):
        pr = self._pr(title="Bump x from 1.0.0 to 2.0.0")
        with patch(
            "app.depsops.pr_judge.get_pull_request", return_value={"mergeable_state": "clean"},
        ), patch("app.depsops.pr_judge.merge_pull_request") as mock_merge:
            action, item = PrJudge(GitHubRepo("u", "r", "token"), has_ci=True).judge(pr)
        assert action == "flagged"
        assert "メジャー" in item["reason"]
        mock_merge.assert_not_called()

    def test_unknown_bump_flags_without_merging(self):
        pr = self._pr(title="Bump x and y in /dashboard")
        with patch(
            "app.depsops.pr_judge.get_pull_request", return_value={"mergeable_state": "clean"},
        ), patch("app.depsops.pr_judge.merge_pull_request") as mock_merge:
            action, item = PrJudge(GitHubRepo("u", "r", "token"), has_ci=True).judge(pr)
        assert action == "flagged"
        assert "判定不可" in item["reason"]
        mock_merge.assert_not_called()

    def test_unstable_state_flags_without_merging(self):
        with patch(
            "app.depsops.pr_judge.get_pull_request", return_value={"mergeable_state": "unstable"},
        ), patch("app.depsops.pr_judge.merge_pull_request") as mock_merge:
            action, item = PrJudge(GitHubRepo("u", "r", "token"), has_ci=True).judge(self._pr())
        assert action == "flagged"
        mock_merge.assert_not_called()

    def test_clean_minor_with_ci_merges(self):
        with patch(
            "app.depsops.pr_judge.get_pull_request", return_value={"mergeable_state": "clean"},
        ), patch("app.depsops.pr_judge.merge_pull_request") as mock_merge:
            action, item = PrJudge(GitHubRepo("u", "r", "token"), has_ci=True).judge(self._pr())
        assert action == "merged"
        assert item["repo_full_name"] == "u/r"
        assert item["is_security_update"] is None  # alert_package_names未指定時
        mock_merge.assert_called_once()

    def test_records_security_update_flag_when_alert_matches(self):
        pr = self._pr(title="Bump requests from 1.0.0 to 1.0.1")
        with patch(
            "app.depsops.pr_judge.get_pull_request", return_value={"mergeable_state": "clean"},
        ), patch("app.depsops.pr_judge.merge_pull_request"):
            action, item = PrJudge(
                GitHubRepo("u", "r", "token"), has_ci=True, alert_package_names={"requests"},
            ).judge(pr)
        assert action == "merged"
        assert item["is_security_update"] is True

    def test_records_security_update_false_when_no_alert_matches(self):
        pr = self._pr(title="Bump requests from 1.0.0 to 1.0.1")
        with patch(
            "app.depsops.pr_judge.get_pull_request", return_value={"mergeable_state": "clean"},
        ), patch("app.depsops.pr_judge.merge_pull_request"):
            action, item = PrJudge(
                GitHubRepo("u", "r", "token"), has_ci=True, alert_package_names=set(),
            ).judge(pr)
        assert action == "merged"
        assert item["is_security_update"] is False

    def test_extracts_compatibility_badge_url_from_pr_detail_body(self):
        pr = self._pr(title="Bump requests from 1.0.0 to 1.0.1")
        detail = {
            "mergeable_state": "clean",
            "body": (
                "[![Dependabot compatibility score]"
                "(https://dependabot-badges.githubapp.com/badges/compatibility_score"
                "?dependency-name=requests&package-manager=pip"
                "&previous-version=1.0.0&new-version=1.0.1)](https://docs.github.com/x)"
            ),
        }
        with patch("app.depsops.pr_judge.get_pull_request", return_value=detail), \
             patch("app.depsops.pr_judge.merge_pull_request"):
            action, item = PrJudge(GitHubRepo("u", "r", "token"), has_ci=True).judge(pr)
        assert action == "merged"
        assert item["compatibility_badge_url"] == (
            "https://dependabot-badges.githubapp.com/badges/compatibility_score"
            "?dependency-name=requests&package-manager=pip"
            "&previous-version=1.0.0&new-version=1.0.1"
        )

    def test_compatibility_badge_url_is_none_when_absent_from_body(self):
        with patch(
            "app.depsops.pr_judge.get_pull_request",
            return_value={"mergeable_state": "clean", "body": "no badge here"},
        ), patch("app.depsops.pr_judge.merge_pull_request"):
            action, item = PrJudge(GitHubRepo("u", "r", "token"), has_ci=True).judge(self._pr())
        assert action == "merged"
        assert item["compatibility_badge_url"] is None
