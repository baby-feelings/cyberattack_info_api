"""app.audit（監査ログ）と、鍵の更新期限の通知（Issue #406）のテスト。"""
# ruff: noqa: E501 - 試験データの表（1行に1件）を、読みやすい形で並べるため
import os
from datetime import UTC, date, datetime, timedelta
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

import pytest  # noqa: E402
from pydantic import ValidationError  # noqa: E402

from app.audit import recorder  # noqa: E402
from app.audit.models import AuditLog  # noqa: E402
from app.auth.session import create_session_token  # noqa: E402
from app.core.config import Settings  # noqa: E402
from app.core.notifications.secret_expiry import ExpiringSecret, SecretExpiryNotifier  # noqa: E402
from app.jobs import secret_expiry  # noqa: E402

HEADERS = {"X-API-KEY": "test-api-key-for-pytest"}


class TestRecorder:
    def test_outcomes(self):
        assert [recorder.outcome_of(s) for s in (200, 201, 302, 401, 403, 429, 500, 503, None)] == [
            "ok", "ok", "ok", "denied", "denied", "throttled", "error", "error", "ok"]

    def test_record_and_cleanup(self, db_session):
        recorder.record_audit("alice", "mcp_token_issued id=1", "ok", 200)
        recorder.record_audit("x" * 300, "y" * 500, "denied", 403)    # 長すぎる値は、切る
        db_session.add(AuditLog(occurred_at=datetime.now(UTC) - timedelta(days=400), actor="old", action="a", outcome="ok"))
        db_session.commit()

        rows = db_session.query(AuditLog).filter(AuditLog.actor != "old").all()
        assert len(rows) == 2 and max(len(r.action) for r in rows) == 200 and max(len(r.actor) for r in rows) == 100

        assert recorder.delete_old_audit_logs() == 1
        assert db_session.query(AuditLog).filter_by(actor="old").count() == 0

    def test_a_failure_to_write_never_breaks_the_caller(self):
        with patch.object(recorder, "SessionLocal", side_effect=RuntimeError("db down")):
            recorder.record_audit("a", "b")        # 例外を送出しない


class TestMiddleware:
    def test_state_changing_admin_calls_are_recorded_with_the_path_only(self, client, db_session):
        with patch("app.depscan.router.run_in_background"):
            client.post("/admin/depscan-crawl?force=true", headers=HEADERS)

        [row] = db_session.query(AuditLog).all()
        assert (row.actor, row.action, row.outcome, row.status_code) == ("api-key", "POST /admin/depscan-crawl", "ok", 202)
        # クエリ・ヘッダーの値は、記録しない
        assert "force" not in row.action and "test-api-key" not in repr((row.actor, row.action))

    def test_failed_authentication_is_recorded_as_denied_even_for_reads(self, client, db_session):
        client.post("/admin/depscan-crawl", headers={"X-API-KEY": "wrong-key"})
        client.get("/auth/notification-settings")                  # 認証なし

        rows = db_session.query(AuditLog).order_by(AuditLog.id).all()
        assert [(r.actor, r.outcome) for r in rows] == [("api-key", "denied"), ("anonymous", "denied")]

    def test_successful_reads_and_non_audited_paths_are_not_recorded(self, client, db_session):
        client.get("/api/kev", headers=HEADERS)
        client.get("/health")
        token = create_session_token("alice")
        client.get("/auth/notification-settings", headers={"Authorization": f"Bearer {token}"})

        assert db_session.query(AuditLog).count() == 0

    def test_session_callers_are_labelled_session(self, client, db_session):
        token = create_session_token("alice")
        client.put("/auth/notification-settings", headers={"Authorization": f"Bearer {token}"}, json={"slack_webhook_url": "bad"})

        row = db_session.query(AuditLog).one()
        assert row.actor == "session" and row.action == "PUT /auth/notification-settings"

    def test_mcp_token_operations_are_recorded_with_the_user_name_once(self, client, db_session):
        token = create_session_token("alice")
        auth = {"Authorization": f"Bearer {token}"}

        issued = client.post("/auth/mcp-token", headers=auth, json={"days": 7}).json()
        client.delete(f"/auth/mcp-tokens/{issued['id']}", headers=auth)

        rows = db_session.query(AuditLog).order_by(AuditLog.id).all()
        assert [(r.actor, r.action) for r in rows] == [
            ("alice", f"mcp_token_issued id={issued['id']}"), ("alice", f"mcp_token_revoked id={issued['id']}")]
        # トークンの値は、記録しない
        assert issued["token"] not in repr([r.action for r in rows])

    def test_throttled_requests_are_recorded(self, db_session):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from app.core import rate_limit
        from app.core.rate_limit import RateLimiter, RateLimitMiddleware

        app = FastAPI()
        app.add_middleware(RateLimitMiddleware, limiter=RateLimiter(1, 5, 60.0))
        app.add_middleware(recorder.AuditMiddleware)

        @app.post("/admin/x")
        def x():
            return {}

        with patch.object(rate_limit.settings, "RATE_LIMIT_ENABLED", True):
            client = TestClient(app)
            client.post("/admin/x")
            client.post("/admin/x")

        assert [r.outcome for r in db_session.query(AuditLog).order_by(AuditLog.id)] == ["ok", "throttled"]


class TestAuditApi:
    def test_requires_the_admin_key_and_lists_newest_first(self, client, db_session):
        assert client.get("/api/audit-logs").status_code in (401, 403)
        recorder.record_audit("a", "first", "ok", 200)
        recorder.record_audit("b", "second", "denied", 403)

        body = client.get("/api/audit-logs", headers=HEADERS).json()
        denied = client.get("/api/audit-logs?outcome=denied&limit=1", headers=HEADERS).json()

        assert [r["action"] for r in body["data"] if r["action"] in ("first", "second")] == ["second", "first"]
        assert [r["action"] for r in denied["data"]] == ["second"]
        assert set(body["data"][0]) == {"occurred_at", "actor", "action", "outcome", "status_code"}   # IP等は無い


class TestSecretExpiry:
    TODAY = date(2026, 11, 1)

    def _settings(self, **values):
        base = {"API_KEY_EXPIRES_ON": "", "GITHUB_TOKEN_EXPIRES_ON": "", "SECRETS_EXPIRY_NOTICE_DAYS": 14}
        base.update(values)
        return patch.multiple(secret_expiry.settings, **base)

    def test_secrets_without_a_deadline_are_ignored(self):
        with self._settings():
            assert secret_expiry.expiring_secrets(self.TODAY) == []

    def test_secrets_inside_the_notice_window_and_expired_ones_are_listed(self):
        with self._settings(API_KEY_EXPIRES_ON="2026-11-10", GITHUB_TOKEN_EXPIRES_ON="2026-10-30"):
            found = secret_expiry.expiring_secrets(self.TODAY)

        assert [(s.name, s.days_left) for s in found] == [("API_KEY（管理者用）", 9), ("GITHUB_TOKEN", -2)]

    def test_secrets_far_from_their_deadline_are_not_listed(self):
        with self._settings(API_KEY_EXPIRES_ON="2027-01-01"):
            assert secret_expiry.expiring_secrets(self.TODAY) == []

    def test_the_job_notifies_and_cleans_up_and_survives_a_cleanup_failure(self):
        with self._settings(API_KEY_EXPIRES_ON="2026-11-02"), \
             patch.object(secret_expiry, "delete_old_audit_logs", side_effect=RuntimeError("x")) as cleanup, \
             patch.object(secret_expiry, "SecretExpiryNotifier") as notifier:
            notifier.return_value.send.return_value = True
            assert secret_expiry.run_secret_expiry_notice(self.TODAY) is True

        cleanup.assert_called_once()
        assert notifier.call_args.args[0][0].days_left == 1

    def test_the_deadline_settings_are_validated_at_startup(self):
        with pytest.raises(ValidationError):
            Settings(DATABASE_URL="sqlite://", API_KEY="k", GITHUB_USERNAME="u", API_KEY_EXPIRES_ON="2026/11/01")  # type: ignore[call-arg]
        ok = Settings(DATABASE_URL="sqlite://", API_KEY="k", GITHUB_USERNAME="u", API_KEY_EXPIRES_ON="2026-11-01", GITHUB_TOKEN_EXPIRES_ON="")  # type: ignore[call-arg]
        assert ok.API_KEY_EXPIRES_ON == "2026-11-01"

    def test_notifier_message_orders_by_urgency_and_never_contains_a_secret_value(self):
        secrets = [ExpiringSecret("A", "2026-11-10", 9, "rotate A"), ExpiringSecret("B", "2026-10-30", -2, "rotate B")]
        message = SecretExpiryNotifier(secrets, recipients=["h"]).build_message()

        assert message.index("*B*") < message.index("*A*")
        assert "期限切れ（2日前）" in message and "あと9日" in message and "*_EXPIRES_ON" in message
        assert SecretExpiryNotifier([]).has_content() is False
        with patch("app.core.notifications.recipients.resolve_admin_recipient", return_value=["h"]) as admin:
            assert SecretExpiryNotifier(secrets).default_recipients() == ["h"]
        admin.assert_called_once()
