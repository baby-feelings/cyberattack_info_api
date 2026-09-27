# API リファレンス（エンドポイント一覧）

[README.md](../README.md) から分離した詳細ページ。全エンドポイント（`/health` を除く）で
`X-API-KEY` ヘッダーが必要です。curlの実行例・パラメータ詳細・レスポンス例は
**[.claude/skills/api-usage/SKILL.md](../.claude/skills/api-usage/SKILL.md)** に集約しているので
そちらを参照（本ページでは重複を避け、エンドポイント一覧のみ示す）。ローカル開発時は
`http://localhost:8000/docs` でOpenAPI仕様（Swagger UI）も参照できる（本番は無効化）。

| メソッド | パス | 説明 |
|---------|------|------|
| GET | `/api/vulnerabilities` | CISA KEV 一覧（検索・フィルタ・`min_epss`対応） |
| GET | `/api/vulnerabilities/{cve_id}` | CVE 個別取得（`?format=stix`でSTIX 2.1形式、Issue #134） |
| GET | `/api/vulnerabilities/recent` | 直近N日の新規KEV |
| GET | `/api/vulnerabilities/stats` | KEV統計（ベンダー別・月別トレンド） |
| GET | `/api/osv` | OSV 一覧（10エコシステム対応） |
| GET | `/api/osv/{osv_id}` | 同一osv_idの全行取得（`?format=stix`でSTIX Bundle形式、Issue #134） |
| GET | `/api/osv/stats` | OSV統計 |
| GET | `/api/jvn` | JVN 一覧 |
| GET | `/api/jvn/{jvndb_id}` | JVNDB ID個別取得（`?format=stix`でSTIX 2.1形式、Issue #134） |
| GET | `/api/jvn/stats` | JVN統計 |
| GET | `/api/depscan` | DEPSCAN検知結果一覧（`reachability`到達可能性判定・`repo_visibility`・`asset_context`・`priority_reasons`含む） |
| GET | `/api/depscan/stats` | DEPSCAN統計（リポジトリ別・重要度別） |
| GET | `/api/depscan/assets` | リポジトリ資産コンテキスト一覧（Issue #131） |
| GET | `/api/depscan/export` | DEPSCAN検知結果をCycloneDX/SPDX形式でエクスポート（`repo`必須、Issue #133） |
| GET | `/api/codescan` | CODESCAN検知結果一覧（Semgrep静的解析 + gitleaksシークレット検知。`cvss_score`はベストエフォート推定〈Issue #203〉。GitHubログイン必須〈`X-API-KEY`またはセッションJWT、Issue #219〉） |
| GET | `/api/codescan/stats` | CODESCAN統計（リポジトリ別・重要度別） |
| GET | `/api/depsops` | DEPSOPS判定履歴（`is_security_update`・`compatibility_badge_url`含む） |
| GET | `/api/depsops/stats` | DEPSOPSのリポジトリ別未解決PR件数（`(repo, pr_number)`ごとの最新状態のみ集計） |
| GET | `/api/crawler-logs` | クローラー実行ログ |
| GET | `/auth/github/login` | DEPSCANダッシュボードのGitHubログイン開始（ブラウザ専用） |
| POST | `/auth/exchange` | 交換コード→セッションJWT |
| GET | `/auth/scan-status` | オンデマンドスキャン進捗（Bearer認証） |
| GET/PUT/DELETE | `/auth/notification-settings` | ログイン中ユーザーのSlack Webhook通知登録・解除（Bearer認証、Issue #227）。PUTは実際にテスト送信し成功した場合のみ保存 |
| POST | `/admin/crawl` | KEV手動クロール（`?force=true`対応、Issue #239） |
| POST | `/admin/osv-crawl` | OSV手動クロール（`?days=N`・`?force=true`対応） |
| POST | `/admin/jvn-crawl` | JVN手動クロール（`?days=N`・`?force=true`対応） |
| POST | `/admin/depscan-crawl` | DEPSCAN手動実行（`?force=true`対応） |
| PUT | `/admin/depscan/assets/{owner}/{repo}` | リポジトリ資産コンテキスト設定（Upsert、Issue #131） |
| POST | `/admin/codescan-crawl` | CODESCAN手動実行（GitHub全リポジトリをSemgrep + gitleaksで再スキャン。`?force=true`対応） |
| POST | `/admin/dependabot-ops` | DEPSOPS手動実行（安全なPRのみ自動マージ。`?force=true`対応） |
| POST | `/admin/repo-cleanup` | 削除済みリポジトリのDEPSCAN/CODESCAN/DEPSOPSデータ削除を手動実行（Issue #228） |
| POST | `/admin/user-crawl` | 登録済み他ユーザー（`GITHUB_USERNAME`以外、Webhook登録済み）向けDEPSCAN/CODESCAN/DEPSOPSを手動実行（Issue #227） |
| GET | `/taxii2/*` | TAXII 2.1配信（KEV/OSV/JVN 3コレクション購読用、最小実装。Issue #134） |
| GET | `/health` | ヘルスチェック（認証不要） |

クロール系の`/admin/*`（`*-crawl`・`dependabot-ops`）はバックグラウンド実行で即座に202を
返す（結果は`/api/crawler-logs`で確認）。KEV/OSV/JVN/DEPSCAN/CODESCAN/DEPSOPSは
`?force=true`を付けると、同日既に成功実行済みでもスキップせず強制的に再実行する
（Issue #239。動作確認等の明示的な手動再実行用。GitHub Actions・APSchedulerの
自動トリガーは常に`force`無しで呼ぶため二重実行にはならない）。
`PUT /admin/depscan/assets/{owner}/{repo}`は同期的なUpsertのため200を即時返す
（バックグラウンド実行ではない）。

DEPSCANダッシュボードのGitHubログイン方式（使い捨て交換コード＋Bearerトークン、RFC 9700
対応・Safari ITP回避の経緯）や、Dependabot PRのマージ運用ルールは`CLAUDE.md`を参照。
