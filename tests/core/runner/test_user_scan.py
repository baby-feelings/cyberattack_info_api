"""app.core.runner.user_scan.UserScanJob（ユーザー別スキャンの共通の骨格）のテスト。

骨格の責務（開始のログ・セッションを必ず閉じる・失敗を送出しない・`on_error` の呼び出し・
`guard` が個別の失敗を握りつぶす）を、最小のサブクラスで確認する。
"""
import logging
import os
from unittest.mock import MagicMock

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.core.runner.user_scan import UserScanJob  # noqa: E402


class _Job(UserScanJob):
    source = "TEST"

    def __init__(self, session, body=None, scope: str | None = None) -> None:
        super().__init__("alice", "gho_token", lambda: session)
        self._body = body
        self.errors: list[Exception] = []
        if scope is not None:
            self.scope = scope

    def execute(self, db) -> None:
        if self._body:
            self._body(self)

    def on_error(self, db, exc: Exception) -> None:
        self.errors.append(exc)


class TestRun:
    def test_runs_the_body_and_closes_the_session(self):
        session = MagicMock()
        ran = []
        _Job(session, body=lambda job: ran.append(True)).run()
        assert ran == [True]
        session.close.assert_called_once()

    def test_failure_is_not_raised_and_calls_on_error(self, caplog):
        session = MagicMock()

        def boom(job):
            raise RuntimeError("scan failed")

        job = _Job(session, body=boom)
        with caplog.at_level(logging.ERROR):
            job.run()  # 送出しない
        assert [str(e) for e in job.errors] == ["scan failed"]
        session.close.assert_called_once()  # 失敗しても、セッションは閉じる
        assert "TEST (for alice) failed: scan failed" in caplog.text

    def test_logs_the_start_with_the_scope(self, caplog):
        with caplog.at_level(logging.INFO):
            _Job(MagicMock(), scope="on-demand for").run()
        assert "=== TEST (on-demand for alice) started ===" in caplog.text


class TestGuard:
    def test_a_guarded_failure_is_logged_and_the_rest_continues(self, caplog):
        order = []

        def body(job):
            with job.guard("file GitHub issues"):
                raise ValueError("403")
            order.append("after")

        job = _Job(MagicMock(), body=body)
        with caplog.at_level(logging.ERROR):
            job.run()
        assert order == ["after"]
        assert job.errors == []  # guard で握りつぶした失敗は、on_error に渡らない
        assert "TEST (for alice): failed to file GitHub issues: 403" in caplog.text
