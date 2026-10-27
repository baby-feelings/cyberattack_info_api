"""依存パッケージの全量（インベントリ。DEPSCAN）。

DEPSCAN のスキャンのたびに、使っている依存の全量を保存し（`repository`）、そこから
リポジトリごとの閲覧・横断検索（`search`・`router`。条件は `filters`）と、SBOM の全量の
エクスポート（`app.depscan.sbom`）を行う。「脆弱な依存だけ」を保存する検知結果
（`DependencyFinding`）とは別に、使っている依存そのものを扱うため、1つのパッケージにまとめる。
"""
from app.depscan.inventory.repository import RepoDependencyRepository

__all__ = ["RepoDependencyRepository"]
