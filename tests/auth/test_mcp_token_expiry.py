"""app.auth.mcp_token_expiry（期限が近い MCP トークンの Slack 通知）のテスト。"""
import os
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")
os.environ.setdefault("GITHUB_USERNAME", "test-github-user")
os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret-key-for-pytest")
# TOKEN_ENCRYPTION_KEY は tests/conftest.py が先に設定する（鍵の文字列はここに書かない）

import pytest  # noqa: E402

from app.auth.account_store import set_slack_webhook, upsert_user_token  # noqa: E402
from app.auth.mcp_token_expiry import (  # noqa: E402
    find_expiring_tokens,
    run_mcp_token_expiry_notices,
    send_expiry_notices,
)
from app.auth.models import McpToken, UserAccount  # noqa: E402
from app.core.notifications import notify_mcp_token_expiry  # noqa: E402
from tests.conftest import TestSessionLocal  # noqa: E402

_NOW = datetime(2026, 10, 12, 0, 0, tzinfo=UTC)
_HOOK = "https://hooks.slack.com/services/T000/B000/XXXX"
_SEND = "app.auth.mcp_token_expiry.notify_mcp_token_expiry"


def _token(db, token_id, username="alice", days=2, **kwargs) -> McpToken:
    row = McpToken(id=token_id, username=username, expires_at=_NOW + timedelta(days=days), **kwargs)
    db.add(row)
    db.commit()
    return row


def _register(db, username="alice") -> None:
    upsert_user_token(db, username, "gho_dummy")
    set_slack_webhook(db, username, _HOOK)


@pytest.fixture(autouse=True)
def _clean(db_session):
    yield
    db_session.query(McpToken).delete()
    db_session.query(UserAccount).delete()
    db_session.commit()


class TestFindExpiring:
    def test_only_tokens_expiring_within_window(self, db_session):
        _token(db_session, "soon", days=2)
        _token(db_session, "edge", days=3)          # ちょうど3日後は対象
        _token(db_session, "later", days=4)
        _token(db_session, "expired", days=-1)      # 期限切れは対象外
        assert {t.id for t in find_expiring_tokens(db_session, _NOW)["alice"]} == {"soon", "edge"}

    def test_excludes_revoked_and_already_notified(self, db_session):
        _token(db_session, "revoked", revoked_at=_NOW)
        _token(db_session, "notified", expiry_notified_at=_NOW)
        _token(db_session, "ok")
        assert [t.id for t in find_expiring_tokens(db_session, _NOW)["alice"]] == ["ok"]

    def test_groups_by_user(self, db_session):
        _token(db_session, "a", "alice")
        _token(db_session, "b", "bob")
        assert set(find_expiring_tokens(db_session, _NOW)) == {"alice", "bob"}


class TestSendNotices:
    def test_sends_once_to_the_owner_and_marks_notified(self, db_session):
        _register(db_session)
        _token(db_session, "t1", days=2)
        _token(db_session, "t2", days=1)
        with patch(_SEND, return_value=True) as mock_send:
            assert send_expiry_notices(db_session, _NOW) == 1
            # 同じ日に再実行しても、2回目は送らない（通知済み）
            assert send_expiry_notices(db_session, _NOW) == 0
        assert mock_send.call_count == 1
        webhook, dates = mock_send.call_args[0]
        assert webhook == _HOOK
        assert sorted(dates) == ["2026-10-13", "2026-10-14"]  # トークン本体は渡さない
        assert all(db_session.get(McpToken, i).expiry_notified_at for i in ("t1", "t2"))

    def test_does_not_send_to_users_without_webhook_and_stays_unnotified(self, db_session):
        _token(db_session, "t1")  # alice は Slack 未登録
        with patch(_SEND) as mock_send:
            assert send_expiry_notices(db_session, _NOW) == 0
        mock_send.assert_not_called()
        assert db_session.get(McpToken, "t1").expiry_notified_at is None
        # 登録後の実行では通知される
        _register(db_session)
        with patch(_SEND, return_value=True):
            assert send_expiry_notices(db_session, _NOW) == 1

    def test_notifications_disabled_is_treated_as_no_webhook(self, db_session):
        _register(db_session)
        db_session.query(UserAccount).update({"notifications_enabled": False})
        db_session.commit()
        _token(db_session, "t1")
        with patch(_SEND) as mock_send:
            assert send_expiry_notices(db_session, _NOW) == 0
        mock_send.assert_not_called()

    def test_failed_send_is_not_marked_so_it_retries(self, db_session):
        _register(db_session)
        _token(db_session, "t1")
        with patch(_SEND, return_value=False):
            assert send_expiry_notices(db_session, _NOW) == 0
        assert db_session.get(McpToken, "t1").expiry_notified_at is None
        with patch(_SEND, return_value=True):
            assert send_expiry_notices(db_session, _NOW) == 1

    def test_each_user_gets_only_their_own_tokens_and_webhook(self, db_session):
        _register(db_session, "alice")
        upsert_user_token(db_session, "bob", "gho_dummy")
        set_slack_webhook(db_session, "bob", "https://hooks.slack.com/services/T9/B9/BOB")
        _token(db_session, "a1", "alice", days=1)
        _token(db_session, "b1", "bob", days=2)
        with patch(_SEND, return_value=True) as mock_send:
            assert send_expiry_notices(db_session, _NOW) == 2
        calls = {c[0][0]: c[0][1] for c in mock_send.call_args_list}
        assert calls[_HOOK] == ["2026-10-13"]
        assert calls["https://hooks.slack.com/services/T9/B9/BOB"] == ["2026-10-14"]


class TestMessageAndJob:
    def test_message_has_dates_and_guidance_but_no_secret(self):
        with patch("app.core.notifications._send_slack", return_value=True) as mock_slack:
            assert notify_mcp_token_expiry(_HOOK, ["2026-10-14", "2026-10-13"]) is True
        message, url = mock_slack.call_args[0]
        assert url == _HOOK
        assert "2件" in message and "有効期限 2026-10-13" in message
        assert message.index("2026-10-13") < message.index("2026-10-14")  # 期限順
        assert "再発行" in message and "Bearer" not in message

    def test_job_runs_with_given_session_factory(self, db_session):
        _register(db_session)
        row = McpToken(id="t1", username="alice",
                       expires_at=datetime.now(UTC) + timedelta(days=1))
        db_session.add(row)
        db_session.commit()
        with patch(_SEND, return_value=True) as mock_send:
            run_mcp_token_expiry_notices(TestSessionLocal)
        assert mock_send.call_count == 1

    def test_job_swallows_errors(self):
        def broken():
            raise RuntimeError("db down")

        run_mcp_token_expiry_notices(broken)  # 例外を外へ出さない
