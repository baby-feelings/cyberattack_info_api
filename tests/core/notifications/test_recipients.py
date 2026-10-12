"""app.core.notifications.recipients（通知の送信先の解決）のテスト。"""
from app.core.notifications.recipients import resolve_admin_recipient, resolve_recipients

_RECIPIENTS = "app.core.notifications.recipients"


_TEST_URL = "https://hooks.slack.com/services/test"


def test_resolve_recipients_global_crawler_broadcasts_to_all(db_session):
    """KEV等グローバルなクローラー種別は、通知有効な全登録ユーザーへ送る。"""
    from app.auth.account_store import set_slack_webhook, upsert_user_token

    for username in ("alice", "bob"):
        upsert_user_token(db_session, username, "dummy-token")
        set_slack_webhook(db_session, username, f"https://hooks.slack.com/services/{username}")

    recipients = resolve_recipients("KEV")
    assert set(recipients) == {
        "https://hooks.slack.com/services/alice",
        "https://hooks.slack.com/services/bob",
    }


def test_resolve_recipients_repo_scoped_crawler_uses_github_username_only(
    db_session, monkeypatch,
):
    """DEPSCAN等は GITHUB_USERNAME 自身の登録Webhookにのみ送る。"""
    from app.auth.account_store import set_slack_webhook, upsert_user_token

    monkeypatch.setattr(f"{_RECIPIENTS}.settings.GITHUB_USERNAME", "baby-feelings")
    upsert_user_token(db_session, "baby-feelings", "dummy-token")
    set_slack_webhook(db_session, "baby-feelings", "https://hooks.slack.com/services/owner")
    upsert_user_token(db_session, "other-user", "dummy-token")
    set_slack_webhook(db_session, "other-user", "https://hooks.slack.com/services/other")

    recipients = resolve_recipients("DEPSCAN")
    assert recipients == ["https://hooks.slack.com/services/owner"]


def test_resolve_admin_recipient_returns_github_username_webhook_only(db_session, monkeypatch):
    from app.auth.account_store import set_slack_webhook, upsert_user_token

    monkeypatch.setattr(f"{_RECIPIENTS}.settings.GITHUB_USERNAME", "baby-feelings")
    upsert_user_token(db_session, "baby-feelings", "dummy-token")
    set_slack_webhook(db_session, "baby-feelings", "https://hooks.slack.com/services/owner")
    upsert_user_token(db_session, "other-user", "dummy-token")
    set_slack_webhook(db_session, "other-user", "https://hooks.slack.com/services/other")

    assert resolve_admin_recipient() == ["https://hooks.slack.com/services/owner"]


def test_resolve_admin_recipient_empty_when_admin_not_registered(db_session, monkeypatch):
    from app.auth.account_store import set_slack_webhook, upsert_user_token

    monkeypatch.setattr(f"{_RECIPIENTS}.settings.GITHUB_USERNAME", "baby-feelings")
    upsert_user_token(db_session, "other-user", "dummy-token")
    set_slack_webhook(db_session, "other-user", "https://hooks.slack.com/services/other")

    assert resolve_admin_recipient() == []
