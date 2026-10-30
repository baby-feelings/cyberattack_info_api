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
| - | `operating=active\|inactive\|all` | 上の DEPSCAN・CODESCAN・DEPSOPS の一覧・統計共通の絞り込み。運用中／運用停止中（`INACTIVE_REPOS`）で分ける。未指定は `all`（全件） |
| GET | `/api/depscan/dependencies` | 使っている依存パッケージの閲覧・横断検索（`package`部分一致・`version`・`ecosystem`・`repo`・`vulnerable`・`operating`。各行に未解決の検知件数`open_vulnerabilities`。MCP: `search_dependencies`） |
| GET | `/api/depscan/dependencies/repos` | リポジトリごとの依存の数と、未解決の検知がある依存の数（`operating`で絞り込み） |
| GET | `/api/runtimes` | 使っている言語・実行環境（Python・Node.js・Flutter・Dart）の版と状態（`eol`/`eol_soon`/`update_available`/`latest`/`reference`。`repo`・`runtime`・`needs_action`・`operating`。Issue #373） |
| GET | `/api/runtimes/repos` | リポジトリごとの検出数と、対応が必要な数 |
| GET | `/api/runtimes/releases` | 最新版とサポート期限（系列ごと。`recommended`が推奨の系列） |
| GET | `/api/sla` | 脆弱性への対応状況（Issue #404）。DEPSCANの検知の、重要度別の対応期限（CRITICAL 7日・HIGH 30日・MEDIUM 90日・KEV掲載7日。`SLA_*`で変更）を超えた検知と、重要度別・リポジトリ別の件数、平均対応日数（MTTR）。`operating`・`repo`・`owner`・`window_days`（MTTRの集計期間。既定90・最大180）。セッション認証時は本人所有のみ |
| GET | `/api/depscan/assets` | リポジトリ資産コンテキスト一覧（Issue #131） |
| GET | `/api/depscan/export` | DEPSCAN検知結果をCycloneDX/SPDX形式でエクスポート（`repo`必須、Issue #133。`content=inventory`で使っている依存の全量） |
| GET | `/api/codescan` | CODESCAN検知結果一覧（Semgrep静的解析 + gitleaksシークレット検知。`cvss_score`はベストエフォート推定〈Issue #203〉。GitHubログイン必須〈`X-API-KEY`またはセッションJWT、Issue #219〉） |
| GET | `/api/codescan/stats` | CODESCAN統計（リポジトリ別・重要度別） |
| GET | `/api/depsops` | DEPSOPS判定履歴（`is_security_update`・`compatibility_badge_url`含む） |
| GET | `/api/depsops/stats` | DEPSOPSのリポジトリ別未解決PR件数（`(repo, pr_number)`ごとの最新状態のみ集計） |
| GET | `/api/crawler-logs` | クローラー実行ログ |
| GET | `/auth/github/login` | DEPSCANダッシュボードのGitHubログイン開始（ブラウザ専用） |
| GET | `/auth/github/callback` | GitHub OAuthのコールバック（ブラウザ専用。使い捨て交換コード付きでダッシュボードへリダイレクト） |
| POST | `/auth/exchange` | 交換コード→セッションJWT |
| POST | `/auth/refresh` | セッションJWTの有効期間を延長（スライディング更新） |
| GET | `/auth/scan-status` | オンデマンドスキャン進捗（Bearer認証） |
| POST | `/auth/mcp-token` | MCPトークンを発行（Bearer認証・ログイン本人のみ。`{"days": 7\|30\|90}`、既定30。有効10個まで、超過は409）。トークン本体は応答にだけ含まれる |
| GET | `/auth/mcp-tokens` | 自分のMCPトークンの一覧（状態・期限・最終使用。トークン本体は含まない。Bearer認証） |
| DELETE | `/auth/mcp-tokens/{id}` | 自分のMCPトークンを失効（他人のトークンは404。Bearer認証） |
| GET | `/auth/oauth-connections` | OAuth（MCP）で自分が許可した接続中のクライアントの一覧（Bearer認証。他人のものは含まない） |
| DELETE | `/auth/oauth-connections/{client_id}` | 接続を解除（許可をすべて取り消す。他人の接続・未接続は404。手動発行のMCPトークンには触れない。Bearer認証） |
| POST | `/mcp` | リモートMCPサーバー（Streamable HTTP。`X-API-KEY` または `Authorization: Bearer <MCPトークン>`。詳細は [mcp-server.md](mcp-server.md)） |
| GET/PUT/DELETE | `/auth/notification-settings` | ログイン中ユーザーのSlack Webhook通知登録・解除（Bearer認証、Issue #227）。PUTは実際にテスト送信し成功した場合のみ保存 |
| POST | `/admin/crawl` | KEV手動クロール（`?force=true`対応、Issue #239） |
| POST | `/admin/osv-crawl` | OSV手動クロール（`?days=N`・`?force=true`対応） |
| POST | `/admin/jvn-crawl` | JVN手動クロール（`?days=N`・`?force=true`対応） |
| POST | `/admin/depscan-crawl` | DEPSCAN手動実行（`?force=true`対応） |
| POST | `/admin/sla-digest` | 対応状況の週次まとめ（Slack）をいま送る（バックグラウンド） |
| POST | `/admin/runtime-crawl` | 言語・実行環境のバージョン監視の手動実行（`?force=true`対応） |
| PUT | `/admin/depscan/assets/{owner}/{repo}` | リポジトリ資産コンテキスト設定（Upsert、Issue #131） |
| POST | `/admin/codescan-crawl` | CODESCAN手動実行（GitHub全リポジトリをSemgrep + gitleaksで再スキャン。`?force=true`対応） |
| POST | `/admin/dependabot-ops` | DEPSOPS手動実行（安全なPRのみ自動マージ。`?force=true`対応） |
| POST | `/admin/repo-cleanup` | 削除済み・スキャン対象外（`SCAN_EXCLUDE_REPOS`）のリポジトリのDEPSCAN/CODESCAN/DEPSOPSデータ削除（対象外は起票済みIssueも閉じる）を手動実行（Issue #228・#342） |
| POST | `/admin/user-crawl` | 登録済み他ユーザー（`GITHUB_USERNAME`以外、Webhook登録済み）向けDEPSCAN/CODESCAN/DEPSOPSを手動実行（Issue #227） |
| GET | `/taxii2/*` | TAXII 2.1配信（KEV/OSV/JVN 3コレクション購読用、最小実装。Issue #134） |
| GET | `/metrics` | Prometheus用メトリクス（`Authorization: Bearer <METRICS_API_KEY>`。未設定時は503） |
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
