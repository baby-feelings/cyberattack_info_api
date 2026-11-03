"""コード検査ツールの共通の形（Strategy）と、共通の定数。
"""
from abc import ABC, abstractmethod
from typing import Any

# コードスニペットの保存上限文字数（生成物混入等の異常ケースでDBが肥大化しないため）
_MAX_SNIPPET_LEN = 2000


class Scanner(ABC):
    """コード検査ツールの共通の形（Strategy）。`scan` が実行→変換の流れ（Template Method）。

    実行（`run`）の失敗（タイムアウト・出力の解析失敗）は例外として伝わる。呼び出し側
    （`crawler.scan_repo`）がスキャナーごとに独立して捕捉し、一方が失敗しても他方の結果を活かす。
    """

    #: ログ・識別用のツール名（`CodeFinding.tool` と同じ値）
    name: str

    @abstractmethod
    def run(self, target_dir: str) -> Any:
        """ツールを実行し、出力（パース済みの JSON）を返す。"""

    @abstractmethod
    def parse(self, full_name: str, raw: Any, repo_root: str) -> list[dict[str, Any]]:
        """`run` の出力を、`CodeFinding` 相当のレコード辞書リストへ変換する。"""

    def scan(self, full_name: str, repo_root: str) -> list[dict[str, Any]]:
        """1リポジトリ（展開済みのルート）を検査して、レコードを返す。"""
        return self.parse(full_name, self.run(repo_root), repo_root)
