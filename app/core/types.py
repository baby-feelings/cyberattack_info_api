"""アプリ全体で共有する型定義。"""
from typing import Literal

# クローラー種別。write_crawler_log・notify_success/notify_error 等、
# クローラー実行結果を扱う箇所で共通利用する（タイプミスを mypy で検知するため）。
CrawlerType = Literal["KEV", "OSV", "JVN", "DEPSCAN"]
