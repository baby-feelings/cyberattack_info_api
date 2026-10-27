"""app.core.notifications.runtime_alerts（言語・実行環境のバージョンの通知）のテスト。"""
from unittest.mock import patch

from app.core.notifications import runtime_alerts
from app.core.notifications.runtime_alerts import RuntimeAlertNotifier, notify_runtime_alerts

_EOL = {
    "kind": "eol", "runtime_label": "Python", "cycle": "3.10", "latest_version": "3.10.20",
    "eol_date": "2026-10-01", "days_to_eol": -26, "repos": ["alice/old"],
}
_SOON = {
    "kind": "eol_soon", "runtime_label": "Node.js", "cycle": "22", "latest_version": "22.17.1",
    "eol_date": "2027-04-30", "days_to_eol": 156, "repos": ["alice/web", "alice/api"],
}
_NEW = {
    "kind": "new_release", "runtime_label": "Python", "cycle": "3.15", "latest_version": "3.15.2",
    "eol_date": "2031-10-31", "days_to_eol": None, "repos": ["alice/old"],
}


class TestRuntimeAlertNotifier:
    def test_has_no_content_without_alerts(self):
        assert not RuntimeAlertNotifier([]).has_content()
        assert RuntimeAlertNotifier([_EOL]).has_content()

    def test_message_groups_by_kind_with_the_most_urgent_first(self):
        message = RuntimeAlertNotifier([_NEW, _SOON, _EOL]).build_message()

        eol_at = message.index("サポートが終了しました")
        soon_at = message.index("サポート終了が近づいています")
        new_at = message.index("新しい版が公開されました")
        assert eol_at < soon_at < new_at

    def test_message_describes_each_alert(self):
        message = RuntimeAlertNotifier([_EOL, _SOON, _NEW]).build_message()

        assert "*Python 3.10* （2026-10-01 に終了）" in message
        assert "使っているアプリ: `alice/old`" in message
        assert "*Node.js 22* （2027-04-30 に終了。あと 156 日）" in message
        assert "`alice/web`、`alice/api`" in message
        assert "*Python 3.15* （最新 3.15.2）" in message

    def test_message_links_to_the_dashboard(self):
        assert runtime_alerts.DASHBOARD_URL in RuntimeAlertNotifier([_EOL]).build_message()

    def test_only_present_kinds_get_a_heading(self):
        message = RuntimeAlertNotifier([_EOL]).build_message()
        assert "サポートが終了しました" in message
        assert "新しい版が公開されました" not in message

    def test_goes_only_to_the_admin(self):
        with patch(
            "app.core.notifications.runtime_alerts.recipient_resolver.resolve_admin_recipient",
            return_value=["https://hooks.slack.com/services/admin"],
        ) as resolver:
            targets = RuntimeAlertNotifier([_EOL]).default_recipients()
        resolver.assert_called_once()
        assert targets == ["https://hooks.slack.com/services/admin"]


class TestNotifyRuntimeAlerts:
    def test_sends_to_the_given_recipients(self):
        with patch("app.core.notifications.slack.send_slack", return_value=True) as send:
            assert notify_runtime_alerts([_EOL], recipients=["https://hooks.slack.com/x"]) is True
        assert send.call_args.args[1] == "https://hooks.slack.com/x"

    def test_returns_false_when_the_send_fails(self):
        with patch("app.core.notifications.slack.send_slack", return_value=False):
            assert notify_runtime_alerts([_EOL], recipients=["https://hooks.slack.com/x"]) is False

    def test_returns_false_without_alerts_and_sends_nothing(self):
        with patch("app.core.notifications.slack.send_slack") as send:
            assert notify_runtime_alerts([], recipients=["https://hooks.slack.com/x"]) is False
        send.assert_not_called()

    def test_returns_false_without_any_recipient(self):
        with patch(
            "app.core.notifications.runtime_alerts.recipient_resolver.resolve_admin_recipient",
            return_value=[],
        ):
            assert notify_runtime_alerts([_EOL]) is False
