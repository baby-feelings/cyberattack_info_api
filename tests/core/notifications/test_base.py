"""app.core.notifications.base（Notifier の共通フロー）のテスト。"""


_RECIPIENTS = "app.core.notifications.recipients"


class TestNotifierTemplate:
    """Notifier 基底クラスの共通フロー（内容判定 → 送信先解決 → 組み立て → 全送信先へ送信）。"""


    @staticmethod
    def _make(content=True, default=("https://hooks.slack.com/default",), explicit=None):
        from app.core.notifications.base import Notifier

        class FakeNotifier(Notifier):
            built = 0
            resolved = 0

            def has_content(self):
                return content

            def default_recipients(self):
                type(self).resolved += 1
                return list(default)

            def build_message(self):
                type(self).built += 1
                return "msg"

        return FakeNotifier(explicit), FakeNotifier

    def test_sends_one_message_to_every_default_recipient(self):
        from unittest.mock import patch

        notifier, cls = self._make(default=("https://hooks.slack.com/a", "https://hooks.slack.com/b"))
        with patch("app.core.notifications.slack.send_slack") as mock_send:
            notifier.send()
        assert [c.args for c in mock_send.call_args_list] == [
            ("msg", "https://hooks.slack.com/a"), ("msg", "https://hooks.slack.com/b"),
        ]
        assert cls.built == 1  # 本文は送信先の数によらず1回だけ組み立てる

    def test_explicit_recipients_skip_default_resolution(self):
        from unittest.mock import patch

        notifier, cls = self._make(explicit=["https://hooks.slack.com/only"])
        with patch("app.core.notifications.slack.send_slack") as mock_send:
            notifier.send()
        mock_send.assert_called_once_with("msg", "https://hooks.slack.com/only")
        assert cls.resolved == 0

    def test_no_content_resolves_nothing_and_sends_nothing(self):
        from unittest.mock import patch

        notifier, cls = self._make(content=False)
        with patch("app.core.notifications.slack.send_slack") as mock_send:
            notifier.send()
        mock_send.assert_not_called()
        assert cls.resolved == 0 and cls.built == 0

    def test_empty_recipients_builds_no_message(self):
        from unittest.mock import patch

        notifier, cls = self._make(default=())
        with patch("app.core.notifications.slack.send_slack") as mock_send:
            notifier.send()
        mock_send.assert_not_called()
        assert cls.built == 0

    def test_concrete_notifiers_declare_their_default_routes(self):
        """成功通知は種別で解決、エラー通知は常に管理者宛、DEPSCAN/DEPSOPSは各既定経路。"""
        from unittest.mock import patch

        from app.core.notifications.crawler import CrawlerErrorNotifier, CrawlerSuccessNotifier
        from app.core.notifications.dependabot_ops import DependabotOpsNotifier
        from app.core.notifications.dependency_findings import DependencyFindingsNotifier

        with patch(f"{_RECIPIENTS}.resolve_recipients", return_value=["u"]) as r, \
             patch(f"{_RECIPIENTS}.resolve_admin_recipient", return_value=["admin"]) as a:
            assert CrawlerSuccessNotifier("KEV", 1, 0).default_recipients() == ["u"]
            r.assert_called_with("KEV")
            assert DependencyFindingsNotifier([]).default_recipients() == ["u"]
            r.assert_called_with("DEPSCAN")
            assert DependabotOpsNotifier([], []).default_recipients() == ["u"]
            r.assert_called_with("DEPSOPS")
            assert CrawlerErrorNotifier("KEV", "boom").default_recipients() == ["admin"]
            a.assert_called_once()
