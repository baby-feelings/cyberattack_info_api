"""登録済みユーザー自身のリポジトリに対するスキャンの、共通の骨格（Template Method）。

DEPSCAN・CODESCAN・DEPSOPS の「ユーザー別の実行」（Issue #227）は、中身は違うが、次の骨格が同じ。

1. 開始をログに出す
2. DB セッションを開く
3. 本体を実行する（ドメインごとに違う部分）
4. 失敗してもプロセスを止めず、ログに残す（呼び出し元は、ユーザー単位で続行する）
5. DB セッションを必ず閉じる

骨格はここ、本体（`execute`）と失敗時の後始末（`on_error`）だけをドメインに実装させる。
本体の中の「失敗しても全体を止めない」処理は、`guard` で包んで、ログの形をそろえる。
"""
import logging
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class UserScanJob(ABC):
    """1ユーザー分のスキャンの実行（骨格）。`run()` が入口。"""

    # ログの接頭辞（"DEPSCAN"・"CODESCAN"・"DEPSOPS"）
    source: str
    # ログに出す実行の種類。"for" なら "CODESCAN (for alice)"、
    # "on-demand for" なら "DEPSCAN (on-demand for alice)" になる
    scope: str = "for"

    def __init__(self, username: str, token: str, session_factory: Callable[[], Session]) -> None:
        """
        Args:
            username: スキャンするユーザーの GitHub ユーザー名。
            token: そのユーザー自身の GitHub トークン。
            session_factory: DB セッションの生成関数（呼び出し側のモジュールの `SessionLocal`）。
                テストで差し替えやすいよう、骨格では import せず、呼び出し側から受け取る。
        """
        self.username = username
        self.token = token
        self._session_factory = session_factory

    @property
    def tag(self) -> str:
        """ログの接頭辞（例: "CODESCAN (for alice)"）。"""
        return f"{self.source} ({self.scope} {self.username})"

    @abstractmethod
    def execute(self, db: Session) -> None:
        """ドメイン固有の本体。完了のログも、ここで出す。"""

    def on_error(self, db: Session, exc: Exception) -> None:  # noqa: B027
        """本体が失敗したときの後始末（例: 進捗テーブルを error にする）。既定では何もしない。"""

    @contextmanager
    def guard(self, action: str) -> Iterator[None]:
        """1つの処理の失敗を、ログに残して握りつぶす（スキャン全体を失敗させない）。"""
        try:
            yield
        except Exception as exc:
            logger.error("%s: failed to %s: %s", self.tag, action, exc, exc_info=True)

    def run(self) -> None:
        """スキャンを実行する。失敗しても例外は送出しない（ログに残す）。"""
        logger.info("=== %s started ===", self.tag)
        db = self._session_factory()
        try:
            self.execute(db)
        except Exception as exc:
            logger.error("%s failed: %s", self.tag, exc, exc_info=True)
            self.on_error(db, exc)
        finally:
            db.close()
