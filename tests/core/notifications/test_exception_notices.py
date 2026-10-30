"""app.core.notifications.exception_notices（受容の期限・解除の通知）のテスト。"""
from unittest.mock import patch

from app.core.notifications.exception_notices import ExceptionNoticeNotifier

WEBHOOK = ["https://hooks.slack.test/x"]


def _notice(n=1, **kwargs):
    base = {"repo_full_name": "u/app", "label": f"npm / pkg{n} / GHSA-{n}",
            "reason": "修正版が無い", "expires_at": "2026-12-01"}
    base.update(kwargs)
    return base


def _message(notices):
    return ExceptionNoticeNotifier(notices, recipients=WEBHOOK).build_message()


class TestBuildMessage:
    def test_sections_are_ordered_by_urgency(self):
        message = _message({"soon": [_notice(3)], "expired": [_notice(2)], "fixed": [_notice(1)]})

        assert message.index("修正版が公開された") < message.index("期限が切れました")
        assert message.index("期限が切れました") < message.index("期限が近づいています")

    def test_shows_repo_label_reason_and_expiry(self):
        message = _message({"expired": [_notice(1)]})

        assert "`u/app` npm / pkg1 / GHSA-1（期限 2026-12-01） — 理由: 修正版が無い" in message

    def test_omits_the_expiry_when_there_is_none(self):
        message = _message({"fixed": [_notice(1, expires_at=None)]})

        assert "期限 " not in message.split("理由")[0]

    def test_truncates_a_long_list_and_says_how_many_more(self):
        message = _message({"soon": [_notice(i) for i in range(1, 14)]})

        assert "ほか 3件" in message
        assert "pkg10" in message and "pkg11" not in message

    def test_skips_empty_sections(self):
        message = _message({"expired": [_notice(1)], "fixed": [], "soon": []})

        assert "修正版が公開された" not in message
        assert "期限が近づいています" not in message


class TestSend:
    def test_has_content_only_when_something_happened(self):
        empty = ExceptionNoticeNotifier({"fixed": [], "expired": [], "soon": []})
        assert empty.has_content() is False
        assert ExceptionNoticeNotifier({"soon": [_notice()]}).has_content() is True

    def test_sends_nothing_when_empty(self):
        with patch("app.core.notifications.slack.send_slack") as send:
            ok = ExceptionNoticeNotifier({}, recipients=WEBHOOK).send()

        assert ok is False
        send.assert_not_called()

    def test_sends_to_the_given_recipients(self):
        with patch("app.core.notifications.slack.send_slack", return_value=True) as send:
            ok = ExceptionNoticeNotifier({"soon": [_notice()]}, recipients=WEBHOOK).send()

        assert ok is True
        assert send.call_args[0][1] == WEBHOOK[0]

    def test_default_recipient_is_the_admin_only(self):
        with patch(
            "app.core.notifications.recipients.resolve_admin_recipient", return_value=WEBHOOK,
        ) as admin:
            assert ExceptionNoticeNotifier({}).default_recipients() == WEBHOOK

        admin.assert_called_once()
