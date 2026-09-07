"""app.core.background.run_in_background のテスト。

daemon スレッドで実際に実行されるため、完了同期には threading.Event を使う
（関数がごく短時間で終わるとスレッドが即座に終了し threading.enumerate() から
消えてしまうため、スレッドを名前で探して join する方式は使わない）。
"""
import logging
import threading

from app.core.background import run_in_background


def test_runs_function_in_background_thread():
    """渡した関数がバックグラウンドスレッドで実際に呼び出されること。"""
    calls: list[str] = []
    done = threading.Event()

    def fn() -> None:
        calls.append("ran")
        done.set()

    run_in_background("TEST-OK", fn)

    assert done.wait(timeout=2.0)
    assert calls == ["ran"]


class _CaptureHandler(logging.Handler):
    """ログ出力を検知した瞬間に Event をセットするテスト用ハンドラ。

    バックグラウンドスレッド内のロギング完了を、タイミングに依存せず
    確実に待ち合わせるために使う。
    """

    def __init__(self) -> None:
        super().__init__()
        self.event = threading.Event()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)
        self.event.set()


def test_logs_error_and_does_not_propagate_when_function_raises():
    """関数が例外を送出しても呼び出し元には伝播せず、エラーログに記録されること。"""
    logger = logging.getLogger("app.core.background")
    handler = _CaptureHandler()
    logger.addHandler(handler)
    try:
        def _boom() -> None:
            raise RuntimeError("boom")

        run_in_background("TEST-ERR", _boom)
        assert handler.event.wait(timeout=2.0)
    finally:
        logger.removeHandler(handler)

    assert any(
        "Background TEST-ERR failed" in record.getMessage() for record in handler.records
    )
