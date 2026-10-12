"""各ドメイン（KEV/OSV/JVN/DEPSCAN/CODESCAN/DEPSOPS/MCP）を束ねる、定期実行・一括実行の処理。

- `scheduler_jobs`: APScheduler に登録する定期ジョブの定義と登録
- `repo_cleanup`: 削除済みリポジトリのデータ削除（Issue #228）
- `user_crawl_runner`: 登録済み他ユーザー向けの定期実行（Issue #227）
- `repo_cleanup_router` / `user_crawl_router`: それらの手動実行用の管理 API

複数のドメインを知っている「アプリケーション層」の処理のため、基盤（`core`）ではなくここに置く
（`core` は個別のドメインを知らない）。
"""
