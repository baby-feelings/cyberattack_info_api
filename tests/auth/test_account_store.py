"""app.auth.account_store（UserAccountのDBアクセス層、Issue #227）のテスト。"""
from app.auth.account_store import (
    clear_slack_webhook,
    decrypt_account_token,
    get_account,
    get_webhook_for_user,
    list_all_webhooks,
    list_other_registered_accounts,
    set_slack_webhook,
    upsert_user_token,
)


def test_upsert_user_token_creates_new_account(db_session):
    upsert_user_token(db_session, "alice", "token-1")
    account = get_account(db_session, "alice")
    assert account is not None
    assert account.github_username == "alice"
    assert decrypt_account_token(account) == "token-1"


def test_upsert_user_token_updates_existing_account(db_session):
    upsert_user_token(db_session, "alice", "token-1")
    upsert_user_token(db_session, "alice", "token-2")
    account = get_account(db_session, "alice")
    assert decrypt_account_token(account) == "token-2"


def test_set_slack_webhook_requires_existing_account(db_session):
    try:
        set_slack_webhook(db_session, "unknown-user", "https://hooks.slack.com/x")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


def test_set_and_get_webhook_for_user(db_session):
    upsert_user_token(db_session, "alice", "token-1")
    set_slack_webhook(db_session, "alice", "https://hooks.slack.com/services/alice")
    assert get_webhook_for_user(db_session, "alice") == "https://hooks.slack.com/services/alice"


def test_get_webhook_for_user_returns_none_when_disabled(db_session):
    upsert_user_token(db_session, "alice", "token-1")
    set_slack_webhook(db_session, "alice", "https://hooks.slack.com/services/alice")
    account = get_account(db_session, "alice")
    account.notifications_enabled = False
    db_session.commit()
    assert get_webhook_for_user(db_session, "alice") is None


def test_get_webhook_for_user_returns_none_when_unregistered(db_session):
    assert get_webhook_for_user(db_session, "nobody") is None


def test_clear_slack_webhook_unsets_url_but_keeps_account(db_session):
    upsert_user_token(db_session, "alice", "token-1")
    set_slack_webhook(db_session, "alice", "https://hooks.slack.com/services/alice")
    clear_slack_webhook(db_session, "alice")
    account = get_account(db_session, "alice")
    assert account is not None
    assert account.slack_webhook_url is None


def test_clear_slack_webhook_noop_when_no_account(db_session):
    # 存在しないユーザーに対して呼んでも例外にならない
    clear_slack_webhook(db_session, "nobody")


def test_list_all_webhooks_excludes_disabled_and_unregistered(db_session):
    upsert_user_token(db_session, "alice", "t1")
    set_slack_webhook(db_session, "alice", "https://hooks.slack.com/services/alice")
    upsert_user_token(db_session, "bob", "t2")
    set_slack_webhook(db_session, "bob", "https://hooks.slack.com/services/bob")
    upsert_user_token(db_session, "carol", "t3")  # Webhook未登録

    dave_account = get_account(db_session, "carol")
    assert dave_account.slack_webhook_url is None

    result = list_all_webhooks(db_session)
    assert set(result) == {
        "https://hooks.slack.com/services/alice",
        "https://hooks.slack.com/services/bob",
    }


def test_list_other_registered_accounts_excludes_given_username(db_session):
    upsert_user_token(db_session, "baby-feelings", "t0")
    upsert_user_token(db_session, "alice", "t1")
    upsert_user_token(db_session, "bob", "t2")

    others = list_other_registered_accounts(db_session, "baby-feelings")
    usernames = {a.github_username for a in others}
    assert usernames == {"alice", "bob"}


def test_decrypt_account_token_returns_none_on_failure(db_session, monkeypatch):
    upsert_user_token(db_session, "alice", "token-1")
    account = get_account(db_session, "alice")
    monkeypatch.setattr("app.auth.account_store.decrypt_token", lambda _: None)
    assert decrypt_account_token(account) is None
