# あなたの役割と開発方針

## 役割
あなたは、プロのプロダクトマネージャー兼プログラマーです。
これから、**サイバー攻撃情報 API の開発・保守**を行います。

## (重要)最初にやること
```bash
# code-review-graph (https://github.com/tirth8205/code-review-graph)を使える状態にする。
code-review-graph build

# グラフの更新(ビルド後、実行し、グラフの更新を監視するため)
code-review-graph watch
```

---

## プロジェクト概要
米 CISA の KEV・OSV・JVN を毎日自動収集し、REST API として配信するサービス。

| 項目 | 内容 |
|------|------|
| **言語** | Python 3.11 |
| **フレームワーク** | FastAPI 0.141.x |
| **ORM** | SQLAlchemy 2.x（`Mapped` / `mapped_column` スタイル） |
| **スケジューラ** | APScheduler 3.x + GitHub Actions cron（補完） |
| **開発 DB** | SQLite／**本番 DB** | PostgreSQL（Neon） |
| **バリデーション** | Pydantic 2.13.x + pydantic-settings 2.15.x |
| **HTTP クライアント** | httpx／**XML パーサー** | defusedxml |
| **デプロイ先** | OCI（Compute VM、Docker Compose） |
| **AI連携** | リモートMCPサーバー（`/mcp`、`mcp` SDK。`docs/mcp-server.md`） |
| **GitHub** | `https://github.com/baby-feelings/cyberattack_info_api` |

## 開発方針（設計原則）
SOLID / DRY / KISS / YAGNI / 高凝集・低結合 / GRASP / Tell, Don't Ask /
Law of Demeter / Composition over Inheritance / Principle of Least Astonishment /
Fail Fast / Separation of Concerns / Convention over Configuration /
You Build It, You Run It / Continuous Improvement

## コーディングルール
- コード内には、処理が分かるようにコメントを記載してください。
- 開発環境用（`.env.development`）と本番環境用（`.env.production`）の 2 つを使い分けてください。
- テスト用コードも必ず作成してください。

## リファクタリング方針
- 元の機能・仕様を変更してはいけません。外部から見える振る舞い（API・入出力）は変えないでください。
- 内部構造・設計・可読性・保守性を改善してください。

---

## キーコマンド

```bash
alembic upgrade head                                  # マイグレーション適用
alembic revision --autogenerate -m "説明"               # マイグレーション生成
uvicorn app.main:app --reload --env-file .env.development  # 開発サーバー起動
pytest                                                 # テスト（カバレッジ付き）
cd dashboard && npm run e2e                            # ダッシュボードE2E（Playwright。HTMLレポート付き）
ruff check app/ tests/                                 # Lint（`S`=bandit相当を含む）
cd dashboard && npm run lint                           # ESLint（警告数の上限あり。package.json）
deploy/zap/run_zap_scan.ps1                            # OWASP ZAP（Docker Desktop。docs/zap-scan.md）
mypy app/ --ignore-missing-imports                     # 型チェック
pip install -r requirements-dev.txt                    # 開発依存インストール
pip-audit -r requirements.txt --desc                   # 依存脆弱性確認（PYTHONUTF8=1推奨）
```

---

## プロジェクト構成
`app/` はドメイン（KEV / OSV / JVN / DEPSCAN / CODESCAN / DEPSOPS / MCP / クローラーログ / 横断共通処理）単位の
パッケージ。各ドメインは `models.py`（ORM）・`schemas.py`（Pydantic）・`crawler.py`・`router.py`を
1フォルダにまとめ高凝集を保つ。`app/main.py`はルーターinclude・lifespanのみに専念。

```
app/
├── main.py       # FastAPI アプリ・lifespan・ルーター include（定期ジョブは core/scheduler_jobs）
├── auth/         # GitHubログイン・ユーザー別Slack通知登録（UserAccount/account_store）
├── core/         # 横断的インフラ: config/database/auth/background/crawler_runner/crypto/
│                 #   db_utils/notifications/osv_client/registry_client/pagination/repo_cleanup/
│                 #   user_crawl_runner/stix/taxii/schemas/github_http（GitHub API認証・
│                 #   `GitHubApi`）/issue_filing（Issue起票共通化）/list_filters（一覧の絞り込み
│                 #   基底）/scheduler_jobs（定期ジョブ定義）。crawler_runner=`CrawlJob`・
│                 #   notifications=`Notifier`（いずれもTemplate Method）
├── kev/          # CISA KEV（models/schemas/crawler/stix/router）
├── osv/          # OSV（10エコシステム対応、+packages.py）
├── jvn/          # JVN（MyJVN API / RDF-RSS）
├── depscan/      # 依存ライブラリ脆弱性スキャン（+issue_management/priority/sbom/
│                 #   user_scan/github_client/parsers/）
├── depsops/      # Dependabot PR 自動運用（runner/pr_judge/pr_log_repository/classify/github_client/user_scan）
├── codescan/     # 自アプリのコード脆弱性診断（Semgrep静的解析+gitleaksシークレット検知。GitHubログイン
│                 #   必須〈DEPSCANとセッション共有〉。+github_client/issue_management/cvss_mapping。
│                 #   CVSS計算式自体はapp.core.cvss）
├── mcp_server/   # AIエージェント向けリモートMCPサーバー（/mcp、Streamable HTTP。ツール=server.py・
│                 #   認証=auth.py。DEPSCAN/CODESCANは本人所有リポジトリのみ。docs/mcp-server.md）
├── zapscan/      # OWASP ZAP（API Scan）の結果→GitHub Issue起票（`python -m app.zapscan`）。
│                 #   スキャン自体は deploy/zap/（使い捨てAPIコンテナ向け。詳細は docs/zap-scan.md）
└── crawler_logs/ # クローラー実行ログ

tests/        # app/ と同じドメイン構成でミラーリング
dashboard/    # Vercel デプロイの React ダッシュボード（KEV/OSV/JVN/DEPSCAN/CODESCAN の5タブ切替。e2e/にPlaywright）
alembic/      # DBスキーマのマイグレーション（env.py に新規モデルimportが必須）
docs/         # README.mdから分離した詳細ドキュメント（API一覧・環境変数・デプロイ手順等）
.github/workflows/  # ci.yml / deploy.yml / daily-crawl.yml / osv-scanner-*.yml / pip-audit.yml / zap-scan.yml / gitleaks.yml
deploy/       # OCIデプロイ関連（deploy_to_oci.ps1・docker-compose.yml・Caddyfile・grafana/）
```

**各ファイルの役割・設計判断の詳細は `.claude/skills/` 配下のスキルを参照**（トークン節約のため、
常時読み込まれるこのファイルには概要のみを置く。関連作業を始める際に該当スキルを読むこと）:

| スキル | 内容 |
|--------|------|
| `api-usage` | 本番APIの使い方（curl例・MCPサーバー）・フィールド定義・エラーレスポンス |
| `crawler-internals` | KEV/OSV/JVN共通基盤（retry/notifications/pagination等）・STIX/TAXII・Alembic |
| `depscan-depsops` | DEPSCAN/DEPSOPSの検知・優先度推薦・SBOM・自動マージ判定・GitHub OAuth・ユーザー別Slack通知登録 |
| `codescan` | CODESCAN（Semgrep静的解析+gitleaks）の設計判断・tarball取得方式・CVSSベストエフォート推定・ログイン必須と本人所有リポジトリのみの絞り込み |
| `dashboard-frontend` | Reactダッシュボードのコンポーネント構成・集約ロジック・E2E（Playwright）の設計 |
| `deployment-ops` | CI/CD（ESLint・gitleaks・ZAP含む）・OCIデプロイ手順・環境変数・Prometheus/Grafana監視 |

---

## 実装Tips（頻出・全体に関わるもの）
- APIキー比較は `hmac.compare_digest` で定数時間比較する（タイミング攻撃対策）
- ORM定義は `Mapped`/`mapped_column` スタイル（`Column` 直書きは mypy 非互換）
- `Settings()` の呼び出しには `# type: ignore[call-arg]`
- ヘルスチェック等で `db_gen` を使う場合は try の前で `None` 初期化（`UnboundLocalError` 対策）
- `GITHUB_USERNAME` は必須環境変数（デフォルト値なし、未設定だとアプリ全体が起動しない）
- semgrepは`requirements.txt`に入れない（`semgrep-cli.txt`・Dockerfileの専用venv）。依存を狭く
  固定する外部CLIとアプリの依存解決を分けるため。`Dockerfile`に`COPY`を足したら
  `deploy/deploy_to_oci.ps1`の転送対象も更新する（`deployment-ops`スキル参照）
- npmの`package-lock.json`はWindowsで`npm install`/`update`しない（Linux向け依存がロックから欠落し
  CIの`npm ci`が失敗する）。LinuxのDocker（`node:22`）で更新する。手順は`deployment-ops`スキル参照
- MCP（`/mcp`）はRESTの読み取りGETの薄いラッパー。DEPSCAN/CODESCANは本人所有リポジトリのみ見え、
  `PUBLIC_API_KEY`では見えない。MCPトークンは台帳（`mcp_tokens`）で個別に失効でき、台帳に無い
  トークンは拒否（`docs/mcp-server.md`）。`/api/codescan`もセッション認証時は本人所有のみ
- 全レスポンスに`core/security_headers.py`がnosniff等を付与（ZAP指摘対応）
- ruffの`S`ルールの例外は理由付き`noqa`（複数行の呼び出しは指摘された行に付ける）。`.gitleaks.toml`の
  allowlistは`[allowlist]`テーブル（`[[allowlist]]`はgitleaks 8.30で読み込めない）
- `deploy_to_oci.ps1`の出力を`Select-Object -First`等で途中打ち切りしない（スクリプトごと中断される）。
  デプロイ時、起動時のマイグレーションでDBが自動更新される（新テーブルは追加のみ）
- OSV-Scannerの再利用ワークフローは呼び出し側に`security-events: write`が必須（無いと`startup_failure`で
  検査が動かないのに気づけない）。OSVは`requirements.txt`の下限（`>=`）の版を検知する（pip-auditは実インストール版）
- Windows: `python3`は無効なストアスタブのため`python`を使う。日本語コメント絡みのcp932エラーは
  `PYTHONUTF8=1`で解消。テストDB削除は`test_engine.dispose()`してから`os.remove`する

---

## 開発の進め方
作業ごとに `main` から `feat/`・`fix/`・`docs/` 等のブランチを切り、PR → CI（ruff・mypy・pytest・
ESLint・gitleaks 等）→ main へマージ。コミットは `feat:`/`fix:`/`docs:`/`refactor:`/`test:`/`chore:`。
詳細・品質チェック一覧は [docs/development-workflow.md](docs/development-workflow.md)。

---

<!-- code-review-graph MCP tools -->
## MCP Tools: code-review-graph

**IMPORTANT: This project has a knowledge graph. ALWAYS use the
code-review-graph MCP tools BEFORE using Grep/Glob/Read to explore
the codebase.** The graph is faster, cheaper (fewer tokens), and gives
you structural context (callers, dependents, test coverage) that file
scanning cannot.

### When to use graph tools FIRST
- **Exploring code**: `semantic_search_nodes_tool` or `query_graph_tool` instead of Grep
- **Understanding impact**: `get_impact_radius_tool` instead of manually tracing imports
- **Code review**: `detect_changes_tool` + `get_review_context_tool` instead of reading entire files
- **Finding relationships**: `query_graph_tool` with callers_of/callees_of/imports_of/tests_for
- **Architecture questions**: `get_architecture_overview_tool` + `list_communities_tool`

Fall back to Grep/Glob/Read **only** when the graph doesn't cover what you need.

### Key Tools
| Tool | Use when |
| ------ | ---------- |
| `detect_changes_tool` | Reviewing code changes — gives risk-scored analysis |
| `get_review_context_tool` | Need source snippets for review — token-efficient |
| `get_impact_radius_tool` | Understanding blast radius of a change |
| `get_affected_flows_tool` | Finding which execution paths are impacted |
| `query_graph_tool` | Tracing callers, callees, imports, tests, dependencies |
| `semantic_search_nodes_tool` | Finding functions/classes by name or keyword |
| `get_architecture_overview_tool` | Understanding high-level codebase structure |
| `refactor_tool` | Planning renames, finding dead code |

### Workflow
1. The graph auto-updates on file changes (via hooks).
2. Use `detect_changes_tool` for code review.
3. Use `get_affected_flows_tool` to understand impact.
4. Use `query_graph_tool` pattern="tests_for" to check coverage.
