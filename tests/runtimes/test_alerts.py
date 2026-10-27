"""app.runtimes.alerts（言語・実行環境のバージョンの通知の判定と、送信済みの記録）のテスト。"""
import os
from datetime import date
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("API_KEY", "test-api-key-for-pytest")
os.environ.setdefault("ENVIRONMENT", "development")

from app.runtimes.alerts import (  # noqa: E402
    INITIALIZED_KEY,
    RuntimeAlertItem,
    find_alerts,
    send_runtime_alerts,
)
from app.runtimes.models import RepoRuntime, RuntimeAlert, RuntimeRelease  # noqa: E402

TODAY = date(2026, 10, 27)
_NOTIFY = "app.runtimes.alerts.notify_runtime_alerts"


def _release(runtime, cycle, latest, *, eol=None, is_eol=False, lts=False, released=None):
    return RuntimeRelease(
        runtime=runtime, cycle=cycle, latest_version=latest, eol_date=eol,
        is_eol=is_eol, is_lts=lts, release_date=released,
    )


def _use(repo, runtime, cycle, *, pinned=True, path="Dockerfile"):
    return RepoRuntime(
        repo_full_name=repo, runtime=runtime, cycle=cycle, source_path=path, pinned=pinned,
    )


def _seed(db):
    db.add_all([
        _release("python", "3.10", "3.10.20", eol=date(2026, 10, 1), is_eol=True,
                 released=date(2021, 10, 4)),
        _release("python", "3.11", "3.11.16", eol=date(2027, 4, 1), released=date(2022, 10, 24)),
        _release("python", "3.14", "3.14.10", eol=date(2030, 10, 31), released=date(2025, 10, 7)),
        _release("python", "3.15", "3.15.2", eol=date(2031, 10, 31), released=date(2026, 10, 9)),
        _release("nodejs", "24", "24.22.1", eol=date(2028, 4, 30), lts=True,
                 released=date(2025, 5, 6)),
    ])
    db.add_all([
        _use("alice/old", "python", "3.10"),                 # eol
        _use("alice/soon", "python", "3.11"),                # eol_soon（あと 156 日）
        _use("alice/soon", "nodejs", "24", path=".nvmrc"),   # latest
        _use("alice/floor", "python", "3.10", pinned=False, path="pyproject.toml"),  # 下限の指定
    ])
    db.commit()


def _by_kind(alerts):
    return {(a.kind, a.runtime, a.cycle): a for a in alerts}


class TestFindAlerts:
    def test_finds_eol_eol_soon_and_new_release(self, db_session):
        _seed(db_session)
        found = _by_kind(find_alerts(db_session, TODAY))

        assert set(found) == {
            ("eol", "python", "3.10"),
            ("eol_soon", "python", "3.11"),
            ("new_release", "python", "3.15"),  # 公開から 18 日
        }
        eol = found[("eol", "python", "3.10")]
        assert eol.repos == ("alice/old",)  # 下限の指定（alice/floor）は含めない
        soon = found[("eol_soon", "python", "3.11")]
        assert soon.days_to_eol == 156 and soon.eol_date == date(2027, 4, 1)
        assert found[("new_release", "python", "3.15")].repos == (
            "alice/floor", "alice/old", "alice/soon")

    def test_new_release_needs_a_repo_using_that_language(self, db_session):
        # Node.js の新しい系列は、Node.js を使うアプリがあるときだけ
        _seed(db_session)
        db_session.add(_release("dart", "3.14", "3.14.0", released=date(2026, 10, 20)))
        db_session.commit()
        assert ("new_release", "dart", "3.14") not in _by_kind(find_alerts(db_session, TODAY))

    def test_old_cycles_are_not_announced_as_new(self, db_session):
        _seed(db_session)
        # 3.14 は公開から 1 年。新しい版としては通知しない
        assert ("new_release", "python", "3.14") not in _by_kind(find_alerts(db_session, TODAY))

    def test_inactive_repos_are_ignored(self, db_session):
        _seed(db_session)
        with patch("app.core.operating_status.settings.INACTIVE_REPOS", "alice/old"):
            found = _by_kind(find_alerts(db_session, TODAY))
        assert ("eol", "python", "3.10") not in found

    def test_nothing_to_report_without_usage(self, db_session):
        db_session.add(_release("python", "3.15", "3.15.2", released=date(2026, 10, 9)))
        db_session.commit()
        assert find_alerts(db_session, TODAY) == []

    def test_key_is_unique_per_event_and_cycle(self):
        item = RuntimeAlertItem("eol_soon", "python", "3.11", "3.11.16", None, None, ())
        assert item.key == "eol_soon:python:3.11"

    def test_as_dict_carries_what_the_notifier_needs(self, db_session):
        _seed(db_session)
        d = _by_kind(find_alerts(db_session, TODAY))[("eol_soon", "python", "3.11")].as_dict()
        assert d == {
            "kind": "eol_soon", "runtime_label": "Python", "cycle": "3.11",
            "latest_version": "3.11.16", "eol_date": "2027-04-01", "days_to_eol": 156,
            "repos": ["alice/soon"],
        }


class TestSendRuntimeAlerts:
    def test_first_run_records_existing_alerts_without_sending(self, db_session):
        _seed(db_session)
        with patch(_NOTIFY) as notify:
            assert send_runtime_alerts(TODAY) == 0
        notify.assert_not_called()
        keys = {a.alert_key for a in db_session.query(RuntimeAlert).all()}
        assert keys == {
            INITIALIZED_KEY, "eol:python:3.10", "eol_soon:python:3.11", "new_release:python:3.15",
        }

    def test_first_run_with_no_alerts_still_marks_initialized(self, db_session):
        """最初の実行で通知が無くても、印を残す（次回、最初の実行として黙って記録しない）。"""
        with patch(_NOTIFY) as notify:
            send_runtime_alerts(TODAY)
        notify.assert_not_called()
        assert {a.alert_key for a in db_session.query(RuntimeAlert).all()} == {INITIALIZED_KEY}

    def test_sends_only_new_events_after_the_first_run(self, db_session):
        _seed(db_session)
        with patch(_NOTIFY, return_value=True):
            send_runtime_alerts(TODAY)  # 初回: 記録のみ

        # 新しい系列が公開され、別の系列のサポート終了が近づいた
        db_session.add(_release("python", "3.16", "3.16.0", released=date(2026, 10, 26)))
        db_session.commit()
        with patch(_NOTIFY, return_value=True) as notify:
            sent = send_runtime_alerts(TODAY)

        assert sent == 1
        (alerts,), _ = notify.call_args
        assert [(a["kind"], a["cycle"]) for a in alerts] == [("new_release", "3.16")]

    def test_does_not_send_the_same_alert_twice(self, db_session):
        _seed(db_session)
        with patch(_NOTIFY, return_value=True):
            send_runtime_alerts(TODAY)
        db_session.add(_release("python", "3.16", "3.16.0", released=date(2026, 10, 26)))
        db_session.commit()
        with patch(_NOTIFY, return_value=True):
            assert send_runtime_alerts(TODAY) == 1
        with patch(_NOTIFY, return_value=True) as notify:
            assert send_runtime_alerts(TODAY) == 0
        notify.assert_not_called()

    def test_failed_send_is_not_recorded_so_it_is_retried(self, db_session):
        _seed(db_session)
        with patch(_NOTIFY, return_value=True):
            send_runtime_alerts(TODAY)
        db_session.add(_release("python", "3.16", "3.16.0", released=date(2026, 10, 26)))
        db_session.commit()

        with patch(_NOTIFY, return_value=False):
            assert send_runtime_alerts(TODAY) == 0
        assert "new_release:python:3.16" not in {
            a.alert_key for a in db_session.query(RuntimeAlert).all()}

        with patch(_NOTIFY, return_value=True) as notify:
            assert send_runtime_alerts(TODAY) == 1  # 翌日の実行で、もう一度送る
        notify.assert_called_once()

    def test_a_cycle_that_becomes_eol_soon_later_is_sent_once(self, db_session):
        _seed(db_session)
        # 3.11 のサポート終了は 2027-04-01。まだ 180 日より先の日は、通知されない
        far = date(2026, 6, 1)
        with patch(_NOTIFY, return_value=True):
            send_runtime_alerts(far)
        with patch(_NOTIFY, return_value=True) as notify:
            send_runtime_alerts(TODAY)  # 期限間近になった
        (alerts,), _ = notify.call_args
        assert ("eol_soon", "3.11") in [(a["kind"], a["cycle"]) for a in alerts]
