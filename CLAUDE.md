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
| **フレームワーク** | FastAPI 0.115.x |
| **ORM** | SQLAlchemy 2.x（`Mapped` / `mapped_column` スタイル） |
| **スケジューラ** | APScheduler 3.x + GitHub Actions cron（補完） |
| **開発 DB** | SQLite／**本番 DB** | PostgreSQL（Neon） |
| **バリデーション** | Pydantic 2.11.x + pydantic-settings 2.9.x |
| **HTTP クライアント** | httpx／**XML パーサー** | defusedxml |
| **デプロイ先** | OCI（Compute VM、Docker Compose） |
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
ruff check app/ tests/                                 # Lint
mypy app/ --ignore-missing-imports                     # 型チェック
pip install -r requirements-dev.txt                    # 開発依存インストール
pip-audit -r requirements.txt --desc                   # 依存脆弱性確認（PYTHONUTF8=1推奨）
```

---

## プロジェクト構成
`app/` はドメイン（KEV / OSV / JVN / DEPSCAN / DEPSOPS / クローラーログ / 横断共通処理）単位の
パッケージ。各ドメインは `models.py`（ORM）・`schemas.py`（Pydantic）・`crawler.py`・`router.py`を
1フォルダにまとめ高凝集を保つ。`app/main.py`はルーターinclude・lifespanのみに専念。

```
app/
├── main.py       # FastAPI アプリ・lifespan・スケジューラ登録・ルーター include
├── auth/         # GitHub ログイン（DEPSCAN ダッシュボードのアクセス制御）
├── core/         # 横断的インフラ: config/database/auth/background/crawler_runner/
│                 #   db_utils/notifications/osv_client/pagination/stix/taxii/schemas
├── kev/          # CISA KEV（models/schemas/crawler/stix/router）
├── osv/          # OSV（10エコシステム対応、+packages.py）
├── jvn/          # JVN（MyJVN API / RDF-RSS）
├── depscan/      # 依存ライブラリ脆弱性スキャン（+issue_management/priority/sbom/
│                 #   user_scan/github_client/parsers/）
├── depsops/      # Dependabot PR 自動運用（runner/classify/github_client）
├── codescan/     # 自アプリのコード脆弱性診断（Semgrep静的解析。+github_client/
│                 #   issue_management/cvss_mapping。CVSS計算式自体はapp.core.cvss）
└── crawler_logs/ # クローラー実行ログ

tests/        # app/ と同じドメイン構成でミラーリング
dashboard/    # Vercel デプロイの React ダッシュボード（KEV/OSV/JVN/DEPSCAN/CODESCAN の5タブ切替）
alembic/      # DBスキーマのマイグレーション（env.py に新規モデルimportが必須）
.github/workflows/  # ci.yml / deploy.yml / daily-crawl.yml / osv-scanner-*.yml / pip-audit.yml
deploy/       # OCIデプロイ関連（deploy_to_oci.ps1・docker-compose.yml・Caddyfile・grafana/）
```

**各ファイルの役割・設計判断の詳細は `.claude/skills/` 配下のスキルを参照**（トークン節約のため、
常時読み込まれるこのファイルには概要のみを置く。関連作業を始める際に該当スキルを読むこと）:

| スキル | 内容 |
|--------|------|
| `api-usage` | 本番APIの使い方（curl例）・フィールド定義・エラーレスポンス |
| `crawler-internals` | KEV/OSV/JVN共通基盤（retry/notifications/pagination等）・STIX/TAXII・Alembic |
| `depscan-depsops` | DEPSCAN/DEPSOPSの検知・優先度推薦・SBOM・自動マージ判定・GitHub OAuth |
| `codescan` | CODESCAN（Semgrep静的解析）の設計判断・tarball取得方式・CVSSベストエフォート推定 |
| `dashboard-frontend` | Reactダッシュボードのコンポーネント構成・集約ロジック |
| `deployment-ops` | CI/CD・OCIデプロイ手順・環境変数・Prometheus/Grafana監視 |

---

## 実装Tips（頻出・全体に関わるもの）
- APIキー比較は `hmac.compare_digest` で定数時間比較する（タイミング攻撃対策）
- ORM定義は `Mapped`/`mapped_column` スタイル（`Column` 直書きは mypy 非互換）
- `Settings()` の呼び出しには `# type: ignore[call-arg]`
- ヘルスチェック等で `db_gen` を使う場合は try の前で `None` 初期化（`UnboundLocalError` 対策）
- `GITHUB_USERNAME` は必須環境変数（デフォルト値なし、未設定だとアプリ全体が起動しない）
- Windows: `python3`は無効なストアスタブのため`python`を使う。日本語コメント絡みのcp932エラーは
  `PYTHONUTF8=1`で解消。テストDB削除は`test_engine.dispose()`してから`os.remove`する

---

## 開発手順

```bash
# 1. feature ブランチを作成
git checkout -b feature/your-feature-name

# 2. コードを変更・コミット
git add <files>
git commit -m "feat: 機能の説明"

# 3. プッシュして PR を作成
git push -u origin feature/your-feature-name

# 4. CI（ruff・mypy・pytest）が通ったら main へマージ
```

## コミットメッセージ規約

| プレフィックス | 用途 |
|--------------|------|
| `feat:` | 新機能 |
| `fix:` | バグ修正 |
| `docs:` | ドキュメント |
| `refactor:` | リファクタリング |
| `test:` | テスト追加・修正 |
| `chore:` | ビルド・設定変更 |

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
