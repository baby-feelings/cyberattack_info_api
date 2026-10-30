"""app.repo_audit（判定・スコア・収集・保存・API・通知。Issue #398）のテスト。"""
# ruff: noqa: E501 - 試験データの表（1行に1件）を、読みやすい形で並べるため
import os
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import httpx

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.auth.session import create_session_token  # noqa: E402
from app.core.notifications.repo_audit import RepoAuditChangeNotifier  # noqa: E402
from app.repo_audit import checks as c  # noqa: E402
from app.repo_audit import collector  # noqa: E402
from app.repo_audit.crawler import _RepoAuditJob, audit_repo  # noqa: E402
from app.repo_audit.models import RepoAudit  # noqa: E402

HEADERS = {"X-API-KEY": "test-api-key-for-pytest"}
NOW = datetime(2026, 10, 31, tzinfo=UTC)

SECURE = {
    "repo": {
        "private": True, "allow_forking": False,
        "security_and_analysis": {
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "enabled"},
            "dependabot_security_updates": {"status": "enabled"},
        },
    },
    "vulnerability_alerts": True,
    "branch_protection": {
        "required_pull_request_reviews": {"required_approving_review_count": 1},
        "required_status_checks": {"strict": True},
    },
    "keys": [{"id": 1, "title": "deploy", "read_only": True}],
    "hooks": [{"id": 5, "config": {"url": "https://hooks.example/x", "insecure_ssl": "0"}}],
    "collaborators": [{"login": "alice", "role_name": "admin"}],
}


def _by_key(raw):
    return {x.key: x for x in c.evaluate(raw)}


class TestEvaluate:
    def test_a_fully_configured_repository_scores_100(self):
        results = c.evaluate(SECURE)
        assert all(x.status == c.OK for x in results)
        assert c.score(results) == 100

    def test_disabled_features_are_ng_with_a_fix(self):
        raw = {**SECURE, "vulnerability_alerts": False, "repo": {
            "private": True, "allow_forking": False,
            "security_and_analysis": {"secret_scanning": {"status": "disabled"}}}}
        checks = _by_key(raw)

        assert checks["secret_scanning"].status == c.NG and "Secret scanning" in checks["secret_scanning"].fix
        assert checks["dependabot_alerts"].status == c.NG
        # security_and_analysis に載っていない機能は、取得不可（不備と断定しない）
        assert checks["push_protection"].status == c.UNAVAILABLE

    def test_unavailable_items_are_left_out_of_the_score(self):
        raw = {"repo": None, "vulnerability_alerts": None, "branch_protection": None,
               "keys": None, "hooks": None}
        results = c.evaluate(raw)

        assert {x.status for x in results} == {c.UNAVAILABLE}
        assert c.score(results) is None

    def test_private_free_branch_protection_is_not_enforceable_not_a_defect(self):
        checks = _by_key({**SECURE, "branch_protection": "not_enforceable"})
        results = c.evaluate({**SECURE, "branch_protection": "not_enforceable"})

        assert checks["branch_protection"].status == c.NOT_ENFORCEABLE
        assert "強制できません" in checks["branch_protection"].detail
        assert c.score(results) == 100   # 分母に含めない

    def test_branch_protection_without_reviews_or_checks_is_ng(self):
        assert _by_key({**SECURE, "branch_protection": False})["branch_protection"].status == c.NG
        weak = _by_key({**SECURE, "branch_protection": {"required_status_checks": {"strict": True}}})["branch_protection"]
        assert weak.status == c.NG and "必須レビュー" in weak.detail and "必須チェック" not in weak.detail
        weak2 = _by_key({**SECURE, "branch_protection": {"required_pull_request_reviews": {"required_approving_review_count": 1}}})["branch_protection"]
        assert "必須チェック" in weak2.detail

    def test_forking_matters_only_for_private_repositories(self):
        private_open = _by_key({**SECURE, "repo": {**SECURE["repo"], "allow_forking": True}})
        public = _by_key({**SECURE, "repo": {**SECURE["repo"], "private": False, "allow_forking": True}})

        assert private_open["forking"].status == c.NG
        assert "forking" not in public

    def test_writable_deploy_keys_and_insecure_webhooks_are_ng(self):
        checks = _by_key({
            **SECURE,
            "keys": [{"title": "ci", "read_only": False}],
            "hooks": [
                {"id": 1, "config": {"url": "http://plain.example/x?token=SECRET"}},
                {"id": 2, "config": {"url": "https://user:pw@x.example/p", "insecure_ssl": "1"}},
            ],
        })

        assert checks["deploy_keys"].status == c.NG and "ci" in checks["deploy_keys"].detail
        assert checks["webhooks"].status == c.NG and "http://plain.example/x" in checks["webhooks"].detail
        # 認証情報・クエリ（トークン）は、表示に残さない
        assert "SECRET" not in checks["webhooks"].detail and "pw" not in checks["webhooks"].detail

    def test_score_is_weighted(self):
        # secret_scanning(3) が ng・他の点検できた項目は ok → 重みの比で計算する
        results = c.evaluate({**SECURE, "repo": {**SECURE["repo"], "security_and_analysis": {
            "secret_scanning": {"status": "disabled"},
            "secret_scanning_push_protection": {"status": "enabled"},
            "dependabot_security_updates": {"status": "enabled"}}}})
        ok = sum(x.weight for x in results if x.status == c.OK)
        total = sum(x.weight for x in results if x.status in (c.OK, c.NG))

        assert c.score(results) == round(100 * ok / total) < 100

    def test_to_dicts(self):
        assert c.to_dicts(c.evaluate(SECURE))[0]["key"] == "secret_scanning"


class TestSecurityHardening:
    def test_webhook_urls_are_read_from_config_and_sanitized(self):
        hook = {"id": 3, "config": {"url": "https://u:p@h.example:8443/a/b?token=T#frag"}}

        assert c.hook_url(hook).startswith("https://u:p@")
        assert c.sanitize_url(c.hook_url(hook)) == "https://h.example:8443/a/b"
        assert c.hook_url({"url": "http://legacy"}) == "http://legacy"   # 互換
        assert c.hook_url({}) == ""

    def test_the_snapshot_identity_changes_when_a_key_becomes_writable_or_is_replaced(self):
        before = collector.snapshot_of({"keys": [{"id": 1, "title": "ci", "read_only": True}]})
        writable = collector.snapshot_of({"keys": [{"id": 1, "title": "ci", "read_only": False}]})
        replaced = collector.snapshot_of({"keys": [{"id": 2, "title": "ci", "read_only": True}]})

        # 同じ名前でも、権限の変更・差し替えを、変化として検知できる
        assert len(c.diff_snapshot(before, writable)) == 2
        assert len(c.diff_snapshot(before, replaced)) == 2

    def test_the_snapshot_never_holds_credentials_from_webhook_urls(self):
        snap = collector.snapshot_of({"hooks": [{"id": 1, "config": {"url": "https://a:b@h.example/p?k=SECRET"}}]})
        assert snap["hooks"] == ["1:https://h.example/p"]

    def test_a_kind_that_could_not_be_fetched_keeps_the_previous_snapshot(self):
        old = {"keys": ["1:a:ro"], "hooks": ["h"], "collaborators": ["alice:admin"]}
        merged = c.merge_snapshots(old, {"keys": None, "hooks": ["h"], "collaborators": ["alice:admin", "m:write"]})

        assert merged == {"keys": ["1:a:ro"], "hooks": ["h"], "collaborators": ["alice:admin", "m:write"]}
        assert c.merge_snapshots(None, {"keys": None}) == {"keys": None}

    def test_a_change_made_while_the_fetch_failed_is_found_on_the_next_success(self, db_session):
        with patch("app.repo_audit.crawler.collect", return_value=SECURE):
            audit_repo(db_session, {"full_name": "u/app"})
        blind = {**SECURE, "collaborators": None}                       # 取得できなかった回
        with patch("app.repo_audit.crawler.collect", return_value=blind):
            audit_repo(db_session, {"full_name": "u/app"})
        added = {**SECURE, "collaborators": [
            {"login": "alice", "role_name": "admin"}, {"login": "mallory", "role_name": "write"}]}
        with patch("app.repo_audit.crawler.collect", return_value=added):
            changes = audit_repo(db_session, {"full_name": "u/app"})

        assert changes == [{"kind": "collaborators", "change": "added", "name": "mallory:write"}]


class TestDiffSnapshot:
    def test_first_audit_reports_no_changes(self):
        assert c.diff_snapshot(None, {"keys": ["a"], "hooks": [], "collaborators": []}) == []
        assert c.diff_snapshot({}, {"keys": ["a"]}) == []

    def test_added_and_removed_are_reported(self):
        old = {"keys": ["a"], "hooks": ["h"], "collaborators": ["alice"]}
        new = {"keys": ["a", "b"], "hooks": [], "collaborators": ["alice", "mallory"]}

        assert c.diff_snapshot(old, new) == [
            {"kind": "keys", "change": "added", "name": "b"},
            {"kind": "hooks", "change": "removed", "name": "h"},
            {"kind": "collaborators", "change": "added", "name": "mallory"},
        ]

    def test_a_kind_that_could_not_be_fetched_is_not_compared(self):
        assert c.diff_snapshot({"keys": ["a"], "hooks": None}, {"keys": None, "hooks": ["x"]}) == []


def _resp(status=200, body=None, content=b"x"):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = body if body is not None else {}
    resp.content = content
    resp.raise_for_status.side_effect = (
        httpx.HTTPStatusError("x", request=MagicMock(), response=resp) if status >= 500 else None
    )
    return resp


def _repo(routes):
    """パスの末尾で応答を返す、偽のリポジトリ。"""
    api = MagicMock()
    api.get.side_effect = lambda path, **kw: next(
        (r for suffix, r in routes.items() if path.endswith(suffix)), _resp(404))
    repo = MagicMock()
    repo.full_name = "u/app"
    repo.path.side_effect = lambda s: f"/repos/u/app{s}"
    repo.api.return_value.__enter__.return_value = api
    return repo


class TestCollector:
    def test_collects_settings_and_marks_missing_ones(self):
        repo = _repo({
            "/repos/u/app": _resp(body={"private": True}),
            "/vulnerability-alerts": _resp(204, content=b""),
            "/branches/main/protection": _resp(404, {"message": "Branch not protected"}),
            "/keys": _resp(body=[{"id": 9, "title": "k", "read_only": True}]),
            "/hooks": _resp(403),
            "/collaborators?affiliation=direct": _resp(body=[{"login": "alice"}]),
        })

        raw = collector.collect(repo, "main")

        assert raw["repo"] == {"private": True}
        assert raw["vulnerability_alerts"] is True
        assert raw["branch_protection"] is False          # 「保護されていない」
        assert raw["hooks"] is None                       # 取得不可（空ではない）
        assert collector.snapshot_of(raw) == {
            "keys": ["9:k:ro"], "hooks": None, "collaborators": ["alice:unknown"],
        }

    def test_dependabot_alerts_disabled_and_forbidden(self):
        disabled = collector.collect(_repo({"/repos/u/app": _resp(body={})}), "main")
        forbidden = collector.collect(_repo({"/repos/u/app": _resp(body={}), "/vulnerability-alerts": _resp(403)}), "main")

        assert disabled["vulnerability_alerts"] is False
        assert forbidden["vulnerability_alerts"] is None

    def test_branch_protection_variants(self):
        base = {"/repos/u/app": _resp(body={})}
        upgrade = collector.collect(_repo({**base, "/branches/main/protection": _resp(403, {"message": "Upgrade to GitHub Pro or make this repository public"})}), "main")
        forbidden = collector.collect(_repo({**base, "/branches/main/protection": _resp(403, {"message": "denied"})}), "main")
        invisible = collector.collect(_repo({**base, "/branches/main/protection": _resp(404, {"message": "Not Found"})}), "main")
        protected = collector.collect(_repo({**base, "/branches/main/protection": _resp(body={"required_status_checks": {"strict": True}})}), "main")

        assert upgrade["branch_protection"] == "not_enforceable"
        assert forbidden["branch_protection"] is None and invisible["branch_protection"] is None
        assert protected["branch_protection"] == {"required_status_checks": {"strict": True}}

    def test_non_json_error_bodies_and_server_errors(self):
        broken = _resp(403)
        broken.json.side_effect = ValueError("no json")
        raw = collector.collect(_repo({"/repos/u/app": broken}), "main")
        assert raw["repo"] is None

        try:
            collector.collect(_repo({"/repos/u/app": _resp(500)}), "main")
        except httpx.HTTPStatusError:
            return
        raise AssertionError("expected an error")


class TestCrawler:
    REPO_INFO = {"full_name": "u/app", "default_branch": "main"}

    def _audit(self, db, raw):
        with patch("app.repo_audit.crawler.collect", return_value=raw):
            return audit_repo(db, self.REPO_INFO)

    def test_first_audit_stores_the_score_without_changes(self, db_session):
        changes = self._audit(db_session, SECURE)

        row = db_session.query(RepoAudit).one()
        assert changes == [] and row.score == 100
        assert row.snapshot["collaborators"] == ["alice:admin"]

    def test_second_audit_detects_a_new_collaborator_and_updates_the_row(self, db_session):
        self._audit(db_session, SECURE)
        changed = {**SECURE, "collaborators": [
            {"login": "alice", "role_name": "admin"}, {"login": "mallory", "role_name": "write"},
        ]}

        changes = self._audit(db_session, changed)

        assert changes == [{"kind": "collaborators", "change": "added", "name": "mallory:write"}]
        assert db_session.query(RepoAudit).count() == 1
        assert db_session.query(RepoAudit).one().changes == changes

    def test_job_counts_repos_issues_and_changes_and_notifies(self, db_session):
        job = _RepoAuditJob()
        counters = MagicMock(inserted=0, deleted=0, updated=0)
        bad = {**SECURE, "vulnerability_alerts": False}
        with patch("app.repo_audit.crawler.list_target_repos", return_value=[
                self.REPO_INFO, {"full_name": "u/broken"}]), \
             patch("app.repo_audit.crawler.collect", side_effect=[bad, httpx.ConnectError("x")]):
            job.execute(db_session, counters)

        # 通信に失敗したリポジトリは飛ばして続ける
        assert counters.inserted == 1 and counters.updated == 1
        with patch("app.repo_audit.crawler.RepoAuditChangeNotifier") as notifier:
            job.changes = {"u/app": [{"kind": "keys", "change": "added", "name": "k"}]}
            job.after_success(MagicMock(inserted=1, updated=1, deleted=1))
        notifier.return_value.send.assert_called_once()
        with patch("app.repo_audit.crawler.RepoAuditChangeNotifier", side_effect=RuntimeError("x")):
            job.after_success(MagicMock(inserted=1, updated=1, deleted=1))  # 例外を送出しない

    def test_job_result_and_entry_point(self):
        assert _RepoAuditJob().result(MagicMock(inserted=3, deleted=2, updated=1)) == (3, 2, 1)
        from app.repo_audit.crawler import fetch_and_audit_repos
        with patch("app.repo_audit.crawler._RepoAuditJob") as cls:
            cls.return_value.run.return_value = (0, 0, 0)
            assert fetch_and_audit_repos(force=True) == (0, 0, 0)

    def test_audited_repo_without_a_default_branch_uses_main(self, db_session):
        with patch("app.repo_audit.crawler.collect", return_value=SECURE) as collect:
            audit_repo(db_session, {"full_name": "u/app"})
        assert collect.call_args.args[1] == "main"


class TestApi:
    def _seed(self, db_session):
        db_session.add_all([
            RepoAudit(repo_full_name="alice/good", score=100, audited_at=NOW, snapshot={}, changes=[],
                      checks=[{"key": "a", "status": "ok"}]),
            RepoAudit(repo_full_name="alice/bad", score=40, audited_at=NOW, snapshot={}, changes=[],
                      checks=[{"key": "a", "status": "ng"}, {"key": "b", "status": "ng"}]),
            RepoAudit(repo_full_name="bob/none", score=None, audited_at=NOW, snapshot={}, changes=[],
                      checks=[{"key": "a", "status": "unavailable"}]),
        ])
        db_session.commit()

    def test_requires_authentication(self, client):
        assert client.get("/api/repo-audit").status_code in (401, 403)

    def test_lists_worst_first_with_issue_counts(self, client, db_session):
        self._seed(db_session)

        body = client.get("/api/repo-audit", headers=HEADERS).json()

        assert [r["repo_full_name"] for r in body["data"]] == ["alice/bad", "alice/good", "bob/none"]
        assert (body["total"], body["repos_with_issues"]) == (3, 1)
        assert body["data"][0]["issues"] == 2

    def test_only_issues_filter(self, client, db_session):
        self._seed(db_session)
        body = client.get("/api/repo-audit?only_issues=true", headers=HEADERS).json()
        assert [r["repo_full_name"] for r in body["data"]] == ["alice/bad"]

    def test_session_user_sees_only_own_repositories(self, client, db_session):
        self._seed(db_session)
        token = create_session_token("bob")
        body = client.get("/api/repo-audit", headers={"Authorization": f"Bearer {token}"}).json()
        assert [r["repo_full_name"] for r in body["data"]] == ["bob/none"]

    def test_manual_run_needs_the_admin_key(self, client):
        assert client.post("/admin/repo-audit-crawl").status_code in (401, 403)
        with patch("app.repo_audit.router.run_in_background") as run:
            res = client.post("/admin/repo-audit-crawl?force=true", headers=HEADERS)
        assert res.status_code == 202 and run.call_args[0][0] == "REPOAUDIT"


class TestNotifier:
    CHANGES = {"u/app": [{"kind": "keys", "change": "added", "name": "new-key"},
                         {"kind": "collaborators", "change": "removed", "name": "bob"}]}

    def test_has_content_only_with_changes(self):
        assert RepoAuditChangeNotifier({}).has_content() is False
        assert RepoAuditChangeNotifier({"u/app": []}).has_content() is False
        assert RepoAuditChangeNotifier(self.CHANGES).has_content() is True

    def test_message_describes_each_change(self):
        message = RepoAuditChangeNotifier(self.CHANGES, recipients=["h"]).build_message()

        assert "デプロイキーを追加: `new-key`" in message and "共同編集者を削除: `bob`" in message
        assert "乗っ取りの兆候" in message

    def test_external_names_cannot_inject_slack_markup(self):
        evil = {"u/a`b": [{"kind": "keys", "change": "added",
                            "name": "x` <!channel> <https://evil|click> &\nfake line"}]}

        message = RepoAuditChangeNotifier(evil, recipients=["h"]).build_message()

        assert "<!channel>" not in message and "<https://evil" not in message
        assert "&lt;!channel&gt;" in message and "&amp;" in message
        assert "x' &lt;" in message           # バッククォートは、書式を終わらせない
        assert "fake line" in message and "&amp; fake line" in message   # 改行は、1行にまとめる

    def test_long_lists_are_cut(self):
        many = {"u/app": [{"kind": "hooks", "change": "added", "name": f"h{i}"} for i in range(20)]}
        assert "ほか 5件" in RepoAuditChangeNotifier(many, recipients=["h"]).build_message()

    def test_default_recipient_is_the_admin_only(self):
        with patch("app.core.notifications.recipients.resolve_admin_recipient", return_value=["h"]) as admin:
            assert RepoAuditChangeNotifier({}).default_recipients() == ["h"]
        admin.assert_called_once()
