"""POST /admin/user-crawl（Issue #227）のテスト。"""
from unittest.mock import patch

from tests.conftest import TEST_API_KEY

HEADERS = {"X-API-KEY": TEST_API_KEY}


class TestTriggerUserCrawl:
    def test_requires_api_key(self, client):
        resp = client.post("/admin/user-crawl")
        assert resp.status_code == 403

    def test_starts_background_crawl(self, client):
        with patch("app.core.user_crawl_router.run_in_background") as mock_bg:
            resp = client.post("/admin/user-crawl", headers=HEADERS)
        assert resp.status_code == 202
        mock_bg.assert_called_once()
        assert mock_bg.call_args[0][0] == "USER_CRAWL"
