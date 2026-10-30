# プロジェクト構成

[README.md](../README.md) から分離した詳細ページ。`app/` はドメイン（KEV / OSV / JVN /
DEPSCAN / CODESCAN / DEPSOPS / MCP / ZAP / クローラーログ / 横断的共通処理）単位のパッケージ構成。各ドメインが
`models.py`・`schemas.py`・`crawler.py`・`router.py` を1つのフォルダにまとめる。`tests/` も
同じドメイン構成でミラーリングする。

```
cyberattack_info_api/
├── app/
│   ├── main.py                 # FastAPI アプリ本体・ルーター include・lifespan のみに専念（定期ジョブ定義は jobs/scheduler_jobs.py）
│   │                           # （/admin/* は持たない。各ドメインの router.py の admin_router に定義）
│   ├── auth/                   # GitHub ログイン・ユーザーアカウント（models〈UserAccount〉・account_store・
│   │                           # session・github_oauth・dependencies〈ログイン中ユーザー〉・api_key〈X-API-KEY/公開キー/セッションの認証〉）。router.py は
│   │                           # github_router〈ログイン・交換コード〉・account_router〈スキャン進捗・通知設定〉を束ねる。
│   │                           # external_login は、ログインの戻りを別機能（MCP の OAuth）が引き受ける登録口
│   │                           # （auth は mcp_server を知らない。依存は mcp_server → auth の一方向）
│   ├── core/                   # 横断的インフラ（個別のドメインを知らない。config・database・background・crawler_runner・
│   │                           # crypto〈トークン暗号化〉・db_utils・notifications/〈slack・recipients・base・用途別〉・pagination・
│   │                           # osv_client・stix・github/〈api=`GitHubApi`・repo=`GitHubRepo`〈1リポジトリへの共通操作〉・
│   │                           # accounts=所有リポジトリ一覧〉・issue_filing〈DEPSCAN/CODESCAN/ZAPのIssue起票共通処理〉・
│   │                           # list_filters〈一覧APIの絞り込み条件の基底クラス〉・security_headers・共通 schemas。
│   │                           # crawler_runnerは`CrawlJob`、notificationsは`Notifier`の Template Method）
│   ├── jobs/                   # 各ドメインを束ねる定期実行・一括実行（scheduler_jobs〈定期ジョブの定義と登録〉・
│   │                           # repo_cleanup〈削除済みリポジトリのデータ削除、Issue #228〉・
│   │                           # user_crawl_runner〈登録済み他ユーザー向け定期実行、Issue #227〉・各管理API）
│   ├── taxii/                  # STIX 2.1 / TAXII 2.1 配信（KEV・OSV・JVN。router.py）
│   ├── kev/                    # CISA KEV ドメイン（models・schemas・crawler・filters〈一覧の絞り込み条件〉・router〈router + admin_router〉）
│   ├── osv/                    # OSV ドメイン（models・schemas・crawler・filters・router〈router + admin_router〉）
│   ├── jvn/                    # JVN ドメイン（models・schemas・crawler・filters・router〈router + admin_router〉）
│   ├── depscan/                # 依存ライブラリ脆弱性スキャン（DEPSCAN）ドメイン（filters含む）
│   │   └── parsers/            # 10 エコシステム分のロックファイルパーサー
│   ├── depsops/                # Dependabot PR 自動運用（DEPSOPS）ドメイン（models・schemas・router
│   │                           # 〈router + admin_router〉。crawler.py 相当は runner.py〈走査の組み立て〉・pr_judge.py〈PR判定〉・pr_log_repository.py〈履歴DB操作〉。
│   │                           # 登録済み他ユーザー向けのper-user実行はuser_scan.py）
│   ├── runtimes/                # 言語・実行環境（Python/Node.js/Flutter/Dart）の使用版の検出と、最新版・サポート期限（EOL）の判定
│   ├── sla/                     # 脆弱性への対応状況（Issue #404）: policy〈重要度・KEVから対応期限〉・report〈期限超過・MTTRの集計〉・
│   │                           # router〈GET /api/sla・POST /admin/sla-digest〉・digest〈週次まとめのSlack通知ジョブ〉。DBの変更なし
│   ├── audit/                   # 監査ログ（Issue #406）: models・recorder〈記録関数・ミドルウェア・掃除〉・router〈GET /api/audit-logs〉
│   ├── commit_watch/            # コミットの監視（Issue #405）: analysis〈危険なパターン・信頼するコミッターの判定。純粋〉・
│   │                           # crawler〈毎日のジョブ〉・router〈POST /admin/commit-watch-crawl〉
│   ├── external_monitor/        # 公開サイトの外形監視（Issue #401）: probes〈TLS・ヘッダー・露出・DNS・Firestore。SSRF対策〉・
│   │                           # targets〈対象URLの検出〉・crawler〈毎日のジョブ〉・router〈/api/site-monitor〉
│   ├── repo_audit/              # リポジトリの設定の監査（Issue #398）: checks〈判定・スコア・変化の差分。純粋〉・collector〈GitHub API〉・
│   │                           # crawler〈毎日のジョブ〉・router〈/api/repo-audit〉
│   ├── github_alerts/           # GitHubのセキュリティアラート（Issue #402）: client〈取得・正規化。シークレットの値は参照しない〉・
│   │                           # repository〈保存・DEPSCANとの突き合わせ〉・crawler〈毎日のジョブ〉・router〈/api/github-alerts〉
│   ├── finding_exceptions/      # 検知の例外（Issue #403）: models〈finding_exceptions。検知とは別テーブル〉・matching〈同一性キー・除外・照合〉・
│   │                           # repository・router〈/api/exceptions・VEX〉・lifecycle〈期限切れ・修正版の公開の毎日の確認〉・issue_sync〈Issueの整合〉・vex
│   ├── codescan/                # 自アプリコード脆弱性診断（CODESCAN）ドメイン（Semgrep・インフラ設定〈iac_rules〉・Semgrep静的解析 + gitleaks
│   │                           # シークレット検知。issue_management・cvss_mapping含む）
│   ├── mcp_server/             # AIエージェント向けリモートMCPサーバー（/mcp、Streamable HTTP。server〈組み立て〉・
│   │                           # tools〈public/private/identity〉・gateway〈RestGateway〉・oauth/〈OAuth 2.1 認可サーバー〉・auth〈admin/public/userの認証。台帳で失効確認〉。詳細は docs/mcp-server.md）
│   ├── zapscan/                # OWASP ZAPの結果→GitHub Issue起票（`python -m app.zapscan`。docs/zap-scan.md）
│   └── crawler_logs/           # クローラー実行ログドメイン（models・schemas・writer・router）
├── tests/                      # app/ と同じドメイン構成
│   ├── conftest.py             # テスト用フィクスチャ (SQLite テスト DB、全サブフォルダに自動継承)
│   ├── test_main.py            # app.main（health/root）テスト
│   ├── core/ auth/ kev/ osv/ jvn/ depscan/ depsops/ runtimes/ sla/ codescan/ mcp_server/ zapscan/ crawler_logs/
├── dashboard/               # Vercel デプロイの React ダッシュボード（App.tsx は組み立てのみ。タブ定義と
│                           # TabBar/TabPanel/HeaderMenu は components/layout/、ページ送りは shared/TableControls）（KEV・OSV（Pub 含む 10 エコシステム）・JVN・
│                           # DEPSCAN〈GitHub ログイン必須。Dependabot運用状況＝DEPSOPS の判定履歴も統合〉・
│                           # CODESCAN〈GitHub ログイン必須。DEPSCANとセッション共有。CVSSベストエフォート
│                           # 推定値・検知ツールバッジを表示〉を5つの固定タブで切り替え表示。ヘッダーの
│                           # ハンバーガーメニュー「設定」からSlack Webhook通知を登録可能、Issue #227）
│   └── e2e/                 # Playwright E2Eテスト（specs・support/mockApi.ts・scenarios.ts〈網羅率カタログ〉・reporters/）
├── alembic/                 # DBスキーマのマイグレーション管理（app.core.migrate から呼び出す）
│   └── versions/            # マイグレーションスクリプト（Gitで追跡）
├── docs/                    # README.mdから分離した詳細ドキュメント（本ファイル含む）
├── .github/
│   ├── dependabot.yml       # Dependabot（pip: / ・npm: /dashboard、週次で依存更新PRを自動作成）
│   └── workflows/
│       ├── ci.yml                    # CI: lint + type check + test (PR 時に自動実行)
│       ├── deploy.yml                # CD: Vercel デプロイ (dashboard/変更時のmainマージ時のみ自動実行。バックエンドは手動デプロイ)
│       ├── daily-crawl.yml           # 毎日クロール (単一 cron UTC 19:05 で KEV → OSV → JVN → DEPSCAN → CODESCAN → DEPSOPS 順次実行)
│       │                             # （ci.ymlにはdashboard-e2e＝PlaywrightのE2Eジョブも含む）
│       ├── osv-scanner-scheduled.yml # OSV-Scanner: 本リポジトリ自身の依存関係を週次・mainマージ時にスキャン
│       ├── osv-scanner-pr.yml        # OSV-Scanner: PRで新規導入された脆弱性のみを差分検出（security-events: write が必須）
│       ├── pip-audit.yml             # pip-audit: requirements.txtを週次・mainマージ時にスキャン
│       ├── gitleaks.yml              # gitleaks: PR/mainのコミット範囲のシークレット検出（.gitleaks.toml適用）
│       └── zap-scan.yml              # OWASP ZAP API Scan（手動＋定期。使い捨てAPIコンテナのみ対象）
├── deploy/                  # OCIデプロイ関連（deploy_to_oci.ps1・docker-compose.yml・Caddyfile・
│   │                       # Grafanaプロビジョニング設定。秘密情報を含む.env/prometheus.ymlはgit管理外）
│   ├── grafana/             # 運用監視ダッシュボードの自動プロビジョニング設定・ダッシュボードJSON
│   └── zap/                 # OWASP ZAP（docker-compose.yml・Dockerfile.api・run_zap_scan.ps1・reports/）
├── Dockerfile               # バックエンドのコンテナイメージ定義（OCI上でdocker composeがビルド）
├── .env.example         # 環境変数テンプレート
├── .python-version      # Python バージョン固定 (3.13)
├── requirements.txt     # 本番依存パッケージ
├── requirements-dev.txt # 開発・テスト依存パッケージ
├── semgrep-cli.txt      # semgrep（CODESCAN用の外部CLI）。Dockerfileの専用venvへ導入しアプリの依存と隔離
├── zizmor-cli.txt       # zizmor（CODESCANのGitHub Actions診断。外部CLI）。同じく専用venvへ導入
├── pyproject.toml       # ruff（S=bandit相当を含む）/ mypy / pytest 設定
├── .gitleaks.toml       # gitleaks の除外設定（[allowlist] テーブル書式。CODESCAN と CI で使用）
├── security_report.html # セキュリティ脆弱性診断レポート
└── CLAUDE.md            # Claude Code 向け開発ガイド
```
