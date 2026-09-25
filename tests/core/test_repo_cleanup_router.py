"""POST /admin/repo-cleanup（Issue #228）のテスト。"""
from unittest.mock import patch

from tests.conftest import TEST_API_KEY

HEADERS = {"X-API-KEY": TEST_API_KEY}


class TestTriggerRepoCleanup:
    def test_requires_api_key(self, client):
        resp = client.post("/admin/repo-cleanup")
        assert resp.status_code == 403

    def test_starts_background_cleanup(self, client):
        with patch("app.core.repo_cleanup_router.run_in_background") as mock_bg:
            resp = client.post("/admin/repo-cleanup", headers=HEADERS)
        assert resp.status_code == 202
        mock_bg.assert_called_once()
        assert mock_bg.call_args[0][0] == "CLEANUP"
