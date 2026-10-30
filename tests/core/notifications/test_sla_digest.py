"""app.core.notifications.sla_digest（対応状況の週次まとめの Slack 通知）のテスト。"""
from unittest.mock import patch

from app.core.notifications.sla_digest import SlaDigestNotifier

WEBHOOK = ["https://hooks.slack.com/x"]


def _overdue(n, **kwargs):
    base = {
        "repo_full_name": f"u/app{n}", "package_name": f"pkg{n}", "installed_version": "1.0.0",
        "osv_id": f"GHSA-{n}", "severity": "HIGH", "is_kev": False, "is_malicious": False,
        "detected_at": "2026-09-01T00:00:00+00:00", "deadline_days": 30,
        "due_at": "2026-10-01T00:00:00+00:00", "overdue_days": 10 + n,
    }
    base.update(kwargs)
    return base


def _report(overdue=(), **summary):
    items = list(overdue)
    repos = sorted({i["repo_full_name"] for i in items})
    return {
        "mttr_window_days": 90,
        "policy": {"critical_days": 7, "high_days": 30, "medium_days": 90, "kev_days": 7},
        "summary": {
            "open_with_deadline": len(items), "overdue": len(items), "resolved": 4,
            "mttr_days": 12.5, **summary,
        },
        "by_repo": [{"repo_full_name": r, "overdue": 1} for r in repos],
        "overdue": items,
    }


def _message(report):
    return SlaDigestNotifier(report, recipients=WEBHOOK).build_message()


class TestBuildMessage:
    def test_shows_summary_policy_and_mttr(self):
        message = _message(_report([_overdue(1)]))

        assert "脆弱性への対応状況（週次）" in message
        assert "未解決（期限あり）: *1件*" in message
        assert "期限超過: *1件*" in message
        assert "直近90日の解決: 4件" in message
        assert "12.5 日" in message
        assert "CRITICAL 7日 / HIGH 30日 / MEDIUM 90日 / KEV掲載 7日" in message

    def test_lists_overdue_items_most_overdue_first_as_given(self):
        message = _message(_report([_overdue(2), _overdue(1)]))

        assert message.index("pkg2") < message.index("pkg1")
        assert "12日超過（期限30日）" in message

    def test_marks_kev_and_malicious_items(self):
        message = _message(_report([_overdue(1, is_kev=True, is_malicious=True)]))

        assert "🛑[KEV]" in message

    def test_all_clear_when_nothing_is_overdue(self):
        message = _message(_report([]))

        assert ":white_check_mark:" in message
        assert "期限超過（超過日数が多い順）" not in message

    def test_truncates_a_long_list_and_says_how_many_more(self):
        message = _message(_report([_overdue(n) for n in range(1, 16)]))

        assert "…ほか 5件" in message

    def test_mttr_is_a_dash_when_nothing_was_resolved(self):
        message = _message(_report([], mttr_days=None, resolved=0))

        assert "平均対応日数（MTTR）: —" in message

    def test_unknown_severity_is_shown_as_unknown(self):
        message = _message(_report([_overdue(1, severity=None)]))

        assert "（不明）" in message


class TestSend:
    def test_always_has_content_so_the_weekly_report_is_sent(self):
        assert SlaDigestNotifier(_report([]), recipients=WEBHOOK).has_content() is True

    def test_sends_to_the_given_recipients(self):
        with patch("app.core.notifications.slack.send_slack", return_value=True) as mock_send:
            ok = SlaDigestNotifier(_report([_overdue(1)]), recipients=WEBHOOK).send()

        assert ok is True
        assert mock_send.call_args[0][1] == WEBHOOK[0]

    def test_default_recipient_is_the_admin_only(self):
        with patch(
            "app.core.notifications.recipients.resolve_admin_recipient", return_value=WEBHOOK,
        ) as mock_admin:
            assert SlaDigestNotifier(_report([])).default_recipients() == WEBHOOK

        mock_admin.assert_called_once()
