"""依存ライブラリパーサー共通の型定義。"""
from dataclasses import dataclass


@dataclass(frozen=True)
class DependencyRef:
    """ロックファイルから抽出した依存パッケージ1件を表す。"""

    ecosystem: str
    name: str
    version: str
