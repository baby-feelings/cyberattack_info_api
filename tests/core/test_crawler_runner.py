"""app.core.crawler_runner（クローラー共通実行ラッパー・同日重複実行防止）のテスト。

Issue #239: APScheduler（毎日自動実行）とGitHub Actionsのdaily-crawl.yml
（「APSchedulerが不発火だった場合のバックアップ」として無条件に毎日発火）の
二重トリガーにより、全クローラーが実質1日2回実行されていた。KEV/OSV/JVN/
DEPSCAN/CODESCANはUpsertのため実害が薄いが、DEPSOPSは実行ごとに1行追記する
ログ設計のため件数が二重に膨れ上がっていた（本番で総件数2388件中約半数が重複）。
"""
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from app.core.crawler_runner import CrawlCounters, CrawlJob, already_succeeded_today, run_crawler
from app.crawler_logs.models import CrawlerLog


def _make_log(db_session, crawler_type: str, status: str, started_at: datetime) -> None:
    db_session.add(CrawlerLog(
        crawler_type=crawler_type,
        status=status,
        started_at=started_at,
        finished_at=started_at,
        duration_seconds=1.0,
    ))
    db_session.commit()


class TestAlreadySucceededToday:
    def test_returns_false_when_no_logs_exist(self, db_session):
        assert already_succeeded_today("KEV") is False

    def test_returns_true_when_succeeded_earlier_today(self, db_session):
        _make_log(db_session, "KEV", "success", datetime.now(timezone.utc))
        assert already_succeeded_today("KEV") is True

    def test_returns_false_when_only_failed_today(self, db_session):
        """今日の実行が全て失敗（error）なら、まだ成功していないので実行を許可する。"""
        _make_log(db_session, "KEV", "error", datetime.now(timezone.utc))
        assert already_succeeded_today("KEV") is False

    def test_returns_false_when_success_was_yesterday(self, db_session):
        """前日の成功は「今日」の判定に含めない（UTC日付境界で区切る）。"""
        yesterday = datetime.now(timezone.utc) - timedelta(days=1)
        _make_log(db_session, "KEV", "success", yesterday)
        assert already_succeeded_today("KEV") is False

    def test_is_scoped_to_the_specific_crawler_type(self, db_session):
        """他のクローラー種別の成功記録には影響されない。"""
        _make_log(db_session, "OSV", "success", datetime.now(timezone.utc))
        assert already_succeeded_today("KEV") is False


class TestRunCrawlerDeduplication:
    def test_skips_body_when_already_succeeded_today(self, db_session):
        """今日既に成功済みなら body を呼ばずに (0, 0, 0) を返す（force未指定）。"""
        _make_log(db_session, "KEV", "success", datetime.now(timezone.utc))
        mock_body = MagicMock()

        result = run_crawler("KEV", mock_body)

        assert result == (0, 0, 0)
        mock_body.assert_not_called()

    def test_force_bypasses_the_skip(self, db_session):
        """force=True なら今日成功済みでも body を実行する（動作確認用の手動再実行）。"""
        _make_log(db_session, "KEV", "success", datetime.now(timezone.utc))

        def _body(db, counters: CrawlCounters) -> None:
            counters.inserted = 5

        with (
            patch("app.core.crawler_runner.SessionLocal", return_value=db_session),
            patch("app.core.crawler_runner.notify_success"),
        ):
            # run_crawler の finally で閉じられても支障が無いようにする
            db_session.close = MagicMock()
            result = run_crawler("KEV", _body, force=True)

        assert result == (5, 0, 0)

    def test_runs_normally_when_nothing_succeeded_today(self, db_session):
        """今日まだ成功記録が無ければ通常通り body を実行する。"""
        def _body(db, counters: CrawlCounters) -> None:
            counters.inserted = 3

        with (
            patch("app.core.crawler_runner.SessionLocal", return_value=db_session),
            patch("app.core.crawler_runner.notify_success"),
        ):
            db_session.close = MagicMock()
            result = run_crawler("KEV", _body)

        assert result == (3, 0, 0)


class _FakeJob(CrawlJob):
    """CrawlJob の各フックを検証するための最小実装。"""

    crawler_type = "DEPSCAN"

    def __init__(self, *, fail: Exception | None = None, after_fail: Exception | None = None):
        self.fail = fail
        self.after_fail = after_fail
        self.after_called_with: CrawlCounters | None = None

    def execute(self, db, counters: CrawlCounters) -> None:
        counters.inserted = 2
        counters.deleted = 1
        if self.fail:
            raise self.fail

    def after_success(self, counters: CrawlCounters) -> None:
        self.after_called_with = counters
        if self.after_fail:
            raise self.after_fail

    def result(self, counters: CrawlCounters) -> tuple[int, ...]:
        return counters.inserted, counters.deleted, 99

    def skipped_result(self) -> tuple[int, ...]:
        return -1, -1, -1


class TestCrawlJob:
    def test_success_runs_hooks_and_returns_custom_result(self, db_session):
        job = _FakeJob()
        with (
            patch("app.core.crawler_runner.SessionLocal", return_value=db_session),
            patch("app.core.crawler_runner.write_crawler_log") as mock_log,
            patch("app.core.crawler_runner.notify_success") as mock_default_notify,
        ):
            db_session.close = MagicMock()
            result = job.run(force=True)

        assert result == (2, 1, 99)
        assert job.after_called_with is not None and job.after_called_with.inserted == 2
        mock_default_notify.assert_not_called()  # after_success を上書き済みなので既定通知なし
        kwargs = mock_log.call_args.kwargs
        assert kwargs["status"] == "success"
        assert (kwargs["inserted"], kwargs["updated"], kwargs["deleted"]) == (2, 0, 1)
        db_session.close.assert_called_once()

    def test_default_after_success_sends_slack_success_notification(self, db_session):
        def _body(db, counters: CrawlCounters) -> None:
            counters.inserted = 4

        with (
            patch("app.core.crawler_runner.SessionLocal", return_value=db_session),
            patch("app.core.crawler_runner.notify_success") as mock_notify,
        ):
            db_session.close = MagicMock()
            run_crawler("KEV", _body, force=True)

        mock_notify.assert_called_once_with("KEV", 4, 0, 0)

    def test_skip_returns_skipped_result_without_executing(self, db_session):
        _make_log(db_session, "DEPSCAN", "success", datetime.now(timezone.utc))
        job = _FakeJob()

        assert job.run() == (-1, -1, -1)
        assert job.after_called_with is None

    def test_error_logs_partial_counters_notifies_and_reraises(self, db_session):
        job = _FakeJob(fail=RuntimeError("boom"))
        with (
            patch("app.core.crawler_runner.SessionLocal", return_value=db_session),
            patch("app.core.crawler_runner.write_crawler_log") as mock_log,
            patch("app.core.crawler_runner.notify_error") as mock_notify_error,
        ):
            db_session.close = MagicMock()
            try:
                job.run(force=True)
                raise AssertionError("例外が再送出されるはず")
            except RuntimeError as exc:
                assert str(exc) == "boom"

        kwargs = mock_log.call_args.kwargs
        assert kwargs["status"] == "error"
        assert (kwargs["inserted"], kwargs["deleted"]) == (2, 1)  # 失敗時点までの件数を記録
        assert kwargs["error_message"] == "boom"
        mock_notify_error.assert_called_once_with("DEPSCAN", "boom")
        assert job.after_called_with is None  # 失敗時は成功後フックを呼ばない

    def test_after_success_failure_is_not_recorded_as_crawl_error(self, db_session):
        """成功後の通知で例外が出ても、success ログは残り error ログは追加されない。"""
        job = _FakeJob(after_fail=ValueError("notify failed"))
        with (
            patch("app.core.crawler_runner.SessionLocal", return_value=db_session),
            patch("app.core.crawler_runner.write_crawler_log") as mock_log,
            patch("app.core.crawler_runner.notify_error") as mock_notify_error,
        ):
            db_session.close = MagicMock()
            try:
                job.run(force=True)
                raise AssertionError("例外が伝播するはず")
            except ValueError:
                pass

        assert mock_log.call_count == 1
        assert mock_log.call_args.kwargs["status"] == "success"
        mock_notify_error.assert_not_called()
