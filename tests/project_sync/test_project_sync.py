"""GitHub Projects への自動追加（PROJSYNC）のテスト。

GitHub への通信は、`httpx.MockTransport` 相当の差し替え（モック）で行い、実際には呼ばない。
"""
from unittest.mock import MagicMock, patch

import httpx
import pytest

from app.core.config import settings
from app.core.crawler_runner import CrawlCounters
from app.project_sync import crawler as crawler_mod
from app.project_sync.client import (
    ProjectScopeError,
    ProjectSyncError,
    add_item,
    fetch_project,
    graphql,
    list_open_items,
)
from tests.conftest import TEST_API_KEY

HEADERS = {"X-API-KEY": TEST_API_KEY}


def _api(*bodies):
    """`post` が、順に bodies の JSON を返す、GitHubApi のモック。"""
    api = MagicMock()
    api.post.side_effect = [MagicMock(json=MagicMock(return_value=b)) for b in bodies]
    return api


def _page(ids, *, project="PVT_1", has_next=False, cursor=None):
    """Project の項目 1 ページ分の GraphQL 応答。"""
    return {"data": {"user": {"projectV2": {
        "id": project,
        "items": {
            "pageInfo": {"hasNextPage": has_next, "endCursor": cursor},
            "nodes": [{"content": {"id": i}} for i in ids] + [{"content": {}}, None],
        },
    }}}}


class TestGraphql:
    def test_returns_data(self):
        api = _api({"data": {"x": 1}})
        assert graphql(api, "q", {"a": 1}) == {"x": 1}
        assert api.post.call_args.kwargs["json"] == {"query": "q", "variables": {"a": 1}}

    def test_insufficient_scopes_is_a_scope_error(self):
        api = _api({"errors": [{"type": "INSUFFICIENT_SCOPES", "message": "secret-ish"}]})
        with pytest.raises(ProjectScopeError) as exc:
            graphql(api, "q", {})
        # トークンや GitHub の応答の本文を、メッセージに含めない
        assert "secret-ish" not in str(exc.value)

    def test_other_errors_raise_project_sync_error(self):
        api = _api({"errors": [{"message": "boom"}]})
        with pytest.raises(ProjectSyncError, match="boom"):
            graphql(api, "q", {})

    def test_missing_data_is_empty(self):
        assert graphql(_api({}), "q", {}) == {}


class TestFetchProject:
    def test_collects_ids_across_pages_and_skips_empty_content(self):
        api = _api(_page(["I1", "I2"], has_next=True, cursor="c1"), _page(["I3"]))
        project_id, existing = fetch_project(api, "me", 6)
        assert project_id == "PVT_1"
        assert existing == {"I1", "I2", "I3"}
        # 2 ページ目は、前のページのカーソルで取る
        assert api.post.call_args_list[1].kwargs["json"]["variables"]["cursor"] == "c1"

    def test_missing_project_raises(self):
        api = _api({"data": {"user": {"projectV2": None}}})
        with pytest.raises(ProjectSyncError, match="見つかりません"):
            fetch_project(api, "me", 6)


class TestListOpenItems:
    def _repo(self, pages):
        repo = MagicMock()
        repo.path.return_value = "/repos/o/r/issues"
        api = MagicMock()
        api.get.side_effect = [
            MagicMock(json=MagicMock(return_value=p), raise_for_status=MagicMock())
            for p in pages
        ]
        repo.api.return_value.__enter__.return_value = api
        return repo, api

    def test_returns_node_ids_and_urls(self):
        repo, _ = self._repo([[
            {"node_id": "I1", "html_url": "u1", "extra": 1},
            {"node_id": "P1", "html_url": "u2", "pull_request": {}},
        ]])
        assert list_open_items(repo) == [
            {"node_id": "I1", "html_url": "u1"}, {"node_id": "P1", "html_url": "u2"},
        ]

    def test_follows_pages_until_a_short_page(self):
        full = [{"node_id": f"N{i}", "html_url": "u"} for i in range(100)]
        repo, api = self._repo([full, [{"node_id": "last", "html_url": "u"}]])
        assert len(list_open_items(repo)) == 101
        assert api.get.call_count == 2


class TestAddItem:
    def test_sends_project_and_content_ids(self):
        api = _api({"data": {}})
        add_item(api, "PVT_1", "I9")
        variables = api.post.call_args.kwargs["json"]["variables"]
        assert variables == {"project": "PVT_1", "content": "I9"}


class TestJob:
    @pytest.fixture(autouse=True)
    def _enabled(self, monkeypatch):
        monkeypatch.setattr(settings, "PROJSYNC_NUMBER", 6)
        monkeypatch.setattr(settings, "PROJSYNC_MAX_ADD", 300)

    def _run(self, *, existing, items_by_repo, add_side_effect=None):
        counters = CrawlCounters()
        job = crawler_mod._ProjectSyncJob()
        repos = [{"full_name": r} for r in items_by_repo]
        with patch.object(crawler_mod, "GitHubApi") as api_cls, \
             patch.object(crawler_mod, "fetch_project", return_value=("PVT_1", set(existing))), \
             patch.object(crawler_mod, "list_target_repos", return_value=repos), \
             patch.object(
                 crawler_mod, "list_open_items",
                 side_effect=lambda repo: items_by_repo[repo.full_name]
                 if not isinstance(items_by_repo[repo.full_name], Exception)
                 else (_ for _ in ()).throw(items_by_repo[repo.full_name]),
             ), \
             patch.object(crawler_mod, "add_item", side_effect=add_side_effect) as add:
            api_cls.return_value.__enter__.return_value = MagicMock()
            job.execute(MagicMock(), counters)
        return job, counters, add

    def test_adds_only_items_not_in_the_project(self):
        job, counters, add = self._run(
            existing={"I1"},
            items_by_repo={
                "o/a": [{"node_id": "I1", "html_url": "u1"}, {"node_id": "I2", "html_url": "u2"}],
                "o/b": [{"node_id": "I3", "html_url": "u3"}],
            },
        )
        assert [c.args[2] for c in add.call_args_list] == ["I2", "I3"]
        assert counters.inserted == 2 and counters.updated == 0
        assert job.repos_scanned == 2

    def test_a_failing_repo_or_item_does_not_stop_the_rest(self):
        def add_effect(api, project_id, content_id):
            if content_id == "I2":
                raise ProjectSyncError("boom")

        _, counters, add = self._run(
            existing=set(),
            items_by_repo={
                "o/bad": httpx.ConnectError("down"),
                "o/a": [{"node_id": "I2", "html_url": "u2"}, {"node_id": "I3", "html_url": "u3"}],
            },
            add_side_effect=add_effect,
        )
        # リポジトリの取得失敗1件＋追加の失敗1件。成功した1件は、数える
        assert counters.updated == 2 and counters.inserted == 1
        assert add.call_count == 2

    def test_stops_at_the_add_limit(self, monkeypatch):
        monkeypatch.setattr(settings, "PROJSYNC_MAX_ADD", 2)
        _, counters, add = self._run(
            existing=set(),
            items_by_repo={
                "o/a": [{"node_id": f"I{i}", "html_url": "u"} for i in range(5)],
                "o/b": [{"node_id": "Z", "html_url": "u"}],
            },
        )
        assert counters.inserted == 2 and add.call_count == 2

    def test_disabled_when_number_is_zero(self, monkeypatch):
        monkeypatch.setattr(settings, "PROJSYNC_NUMBER", 0)
        with patch.object(crawler_mod, "fetch_project") as fetch:
            counters = CrawlCounters()
            crawler_mod._ProjectSyncJob().execute(MagicMock(), counters)
        fetch.assert_not_called()
        assert counters.inserted == 0

    def test_missing_scope_fails_the_job(self):
        with patch.object(crawler_mod, "GitHubApi"), \
             patch.object(crawler_mod, "fetch_project", side_effect=ProjectScopeError("x")):
            with pytest.raises(ProjectScopeError):
                crawler_mod._ProjectSyncJob().execute(MagicMock(), CrawlCounters())

    def test_result_and_after_success(self):
        job = crawler_mod._ProjectSyncJob()
        job.repos_scanned = 3
        counters = CrawlCounters(inserted=4, updated=1)
        assert job.result(counters) == (4, 1, 3)
        job.after_success(counters)  # 例外なく、ログを出すだけ

    def test_entry_point_runs_the_job(self):
        with patch.object(crawler_mod._ProjectSyncJob, "run", return_value=(1, 0, 2)) as run:
            assert crawler_mod.sync_project_items(force=True) == (1, 0, 2)
        run.assert_called_once_with(force=True)


class TestAdminRouter:
    def test_requires_api_key(self, client):
        assert client.post("/admin/project-sync-crawl").status_code in (401, 403)

    def test_starts_the_job_in_background(self, client):
        with patch("app.project_sync.router.run_in_background") as run:
            res = client.post("/admin/project-sync-crawl?force=true", headers=HEADERS)
        assert res.status_code == 202
        assert run.call_args[0][0] == "PROJSYNC"
