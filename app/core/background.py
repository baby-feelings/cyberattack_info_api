"""クローラーをバックグラウンドスレッドで実行する共通ヘルパー。

Render Free プランのリクエストタイムアウト（~30s）に対し、OSV クロール等の
長時間処理が 502 になるのを避けるため、/admin/*-crawl エンドポイントは
即座に 202 Accepted を返し、実処理は daemon スレッドで実行する。
KEV/OSV/JVN/DEPSCAN の各ドメインルーターから共通で利用する。
"""
import logging
import threading
from collections.abc import Callable

logger = logging.getLogger(__name__)


def run_in_background(name: str, fn: Callable[[], object]) -> None:
    """指定した関数を daemon スレッドでバックグラウンド実行する。

    Args:
        name: ログ出力用のクローラー名（例: "KEV"）
        fn: 実行する関数（引数なし）
    """
    def _wrapper() -> None:
        try:
            fn()
        except Exception as exc:
            logger.error("Background %s failed: %s", name, exc, exc_info=True)

    thread = threading.Thread(target=_wrapper, name=f"crawl-{name}", daemon=True)
    thread.start()
    logger.info("Background %s started (thread=%s)", name, thread.name)
