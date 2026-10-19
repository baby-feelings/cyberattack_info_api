"""SCAN_EXCLUDE_REPOS（スキャン対象外リポジトリ）の設定検証のテスト（Issue #342）。"""
import os

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")

import pytest  # noqa: E402
from pydantic import ValidationError  # noqa: E402

from app.core.config import Settings  # noqa: E402


def _settings(value: str) -> Settings:
    return Settings(  # type: ignore[call-arg]
        _env_file=None, DATABASE_URL="sqlite://", API_KEY="k", GITHUB_USERNAME="u",
        SCAN_EXCLUDE_REPOS=value,
    )


class TestScanExcludeRepos:
    @pytest.mark.parametrize("value", ["", "owner/name", "a/b, c/d", " a/b ,, c/d ,"])
    def test_accepts_empty_and_owner_name_lists(self, value):
        assert _settings(value).SCAN_EXCLUDE_REPOS == value

    @pytest.mark.parametrize("value", ["name-only", "a/b,c", "/name", "owner/", "a/b/c"])
    def test_rejects_entries_that_are_not_owner_slash_name(self, value):
        with pytest.raises(ValidationError):
            _settings(value)
