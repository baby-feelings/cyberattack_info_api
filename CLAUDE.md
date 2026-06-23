# あなたの役割と開発方針

## 役割
あなたは、プロのプロダクトマネージャー兼プログラマーです。  
これから、**サイバー攻撃情報 API の開発・保守**を行います。

---

## プロジェクト概要

米 CISA の Known Exploited Vulnerabilities (KEV) カタログ・OSV (Open Source Vulnerabilities)・JVN (Japan Vulnerability Notes) を毎日自動収集し、REST API として配信するサービスです。

| 項目 | 内容 |
|------|------|
| **言語** | Python 3.11 |
| **フレームワーク** | FastAPI 0.115.x |
| **ORM** | SQLAlchemy 2.x（`Mapped` / `mapped_column` スタイル） |
| **スケジューラ** | APScheduler 3.x（`BackgroundScheduler`）＋ GitHub Actions cron（補完） |
| **開発 DB** | SQLite |
| **本番 DB** | PostgreSQL（Neon マネージドサービス） |
| **バリデーション** | Pydantic 2.11.x + pydantic-settings 2.9.x |
| **HTTP クライアント** | httpx |
| **XML パーサー** | defusedxml（XXE / Billion-laughs 攻撃防止） |
| **デプロイ先** | Render（Web Service） |
| **GitHub** | `https://github.com/baby-feelings/cyberattack_info_api` |

---

## 開発方針（設計原則）

- SOLID 原則
- DRY 原則（Don't Repeat Yourself）
- KISS 原則（Keep It Simple, Stupid）
- YAGNI（You Aren't Gonna Need It）
- 高凝集・低結合（High Cohesion, Low Coupling）
- GRASP 原則
- Tell, Don't Ask
- Law of Demeter（デメテルの法則）
- Composition over Inheritance（継承より合成）
- Principle of Least Astonishment（最小驚愕の原則）
- Fail Fast（早めに失敗させる）
- Separation of Concerns（関心の分離）
- Convention over Configuration（設定より規約）
- You Build It, You Run It
- Continuous Improvement（継続的改善）

---

## コーディングルール

- コード内には、処理が分かるようにコメントを記載してください。
- 開発環境用（`.env.development`）と本番環境用（`.env.production`）の 2 つを使い分けてください。
- テスト用コードも必ず作成してください。

---

## キーコマンド

```bash
# 開発サーバー起動
uvicorn app.main:app --reload --env-file .env.development

# テスト実行（カバレッジ付き）
pytest

# Lint
ruff check app/ tests/

# 型チェック
mypy app/ --ignore-missing-imports

# 依存パッケージインストール（開発）
pip install -r requirements-dev.txt
```

---

## プロジェクト構成

```
app/
├── main.py            # FastAPI アプリ・lifespan・ヘルスチェック
│                      # /admin/crawl・/admin/osv-crawl・/admin/jvn-crawl
├── config.py          # Settings（pydantic-settings）・環境変数管理
├── database.py        # SQLAlchemy エンジン（SQLite/PG 切り替え）・get_db
├── models.py          # ORM モデル（Vulnerability・OsvVulnerability・JvnVulnerability・CrawlerLog）
├── schemas.py         # Pydantic スキーマ（VulnerabilityOut・OsvVulnerabilityOut・JvnVulnerabilityOut 等）
├── auth.py            # X-API-KEY 認証（APIKeyHeader・hmac.compare_digest）
├── db_utils.py        # DB ユーティリティ（year_month_expr: SQLite/PG 両対応の日付フォーマット）
├── cron.py            # CISA KEV クローラー・Upsert ロジック・Slack 通知呼び出し
├── cron_osv.py        # OSV クローラー（REST API 方式・10 エコシステム対応）・Upsert・古いレコード削除・Slack 通知
├── cron_jvn.py        # JVN クローラー（MyJVN API / RDF-RSS）・Upsert・Slack 通知
├── crawler_log.py     # クローラー実行ログ書き込みユーティリティ（write_crawler_log・now_utc）
├── notifications.py   # Slack Webhook 通知（notify_success/notify_error 共通化・エラーサニタイズ）
└── routers/
    ├── vulnerabilities.py  # /api/vulnerabilities エンドポイント（一覧・個別・統計）
    ├── osv.py              # /api/osv エンドポイント（一覧・統計）
    ├── jvn.py              # /api/jvn エンドポイント（一覧・統計）
    └── crawler_logs.py     # /api/crawler-logs エンドポイント（実行ログ一覧）

tests/
├── conftest.py              # テスト DB・client・db_session フィクスチャ
├── test_api.py              # KEV API エンドポイントテスト
├── test_cron.py             # KEV クローラーユニットテスト
├── test_crawler_logs.py     # クローラーログ API テスト
├── test_database.py         # DB エンジン・セッションテスト
├── test_osv.py              # OSV API・クローラーテスト
├── test_jvn.py              # JVN API・クローラーテスト
└── test_notifications.py    # Slack 通知テスト（KEV・OSV・JVN 対応）

dashboard/               # Vercel デプロイの React ダッシュボード
                         # CISA KEV・OSV（Pub 含む 10 エコシステム・180 日表示）・JVN の 3 セクション構成

.github/workflows/
├── ci.yml           # CI: ruff → mypy → pytest（PR 時・Python 3.10/3.11 matrix）
├── deploy.yml       # CD: Render Deploy Hook トリガー（main マージ時）
└── daily-crawl.yml  # 毎日クロール: 単一 cron(UTC 19:05) で KEV → OSV → JVN を順次実行
```

---

## 重要な実装上の注意事項

### API キー認証のタイミング攻撃対策
```python
# ❌ 通常の文字列比較（タイミング攻撃に脆弱）
if api_key != settings.API_KEY:

# ✅ 定数時間比較（hmac.compare_digest）
if not hmac.compare_digest(api_key, settings.API_KEY):
```

### CORS・Swagger の本番制限
- CORS: 本番は `["https://cyberattackinfoapi.vercel.app"]` のみ許可。開発時は localhost も追加
- Swagger UI / ReDoc: `settings.ENVIRONMENT != "production"` の場合のみ有効

### 通知関数の共通化（notifications.py）
`notify_success(crawler_type, inserted, updated, deleted)` と `notify_error(crawler_type, error)` の
2 つの汎用関数に統合。旧関数（`notify_new_vulnerabilities` 等）は後方互換ラッパーとして維持。
エラーメッセージは `_sanitize_error()` で接続文字列マスク + 200 文字制限。

### DB ユーティリティの共通化（db_utils.py）
`year_month_expr(column)` は SQLite / PostgreSQL 両対応の YYYY-MM フォーマット式を返す共通関数。
3 つのルーター（vulnerabilities.py / osv.py / jvn.py）から共通利用する。

### SQLAlchemy 2.x スタイルの使用（mypy 互換）
```python
# ❌ 旧スタイル（mypy エラーが出る）
id: int = Column(Integer, primary_key=True)

# ✅ 新スタイル（Mapped + mapped_column）
id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
```
`pyproject.toml` に `plugins = ["sqlalchemy.ext.mypy.plugin"]` を設定済み。

### pydantic-settings の型無視
```python
# mypy は env_file からの注入を理解できないため type: ignore が必要
settings = Settings()  # type: ignore[call-arg]
```

### ヘルスチェックの UnboundLocalError 対策
```python
db_gen = None  # try ブロックの前で必ず初期化する
try:
    db_gen = get_db()
    ...
finally:
    if db_gen is not None:  # ガードなしだと UnboundLocalError
        ...
```

### SQLite / PostgreSQL 切り替え
`DATABASE_URL` が `sqlite://` で始まる場合は `check_same_thread=False` と PRAGMA 設定を自動適用。  
PostgreSQL の場合は `pool_pre_ping=True` で接続断を自動検出。

### OSV クローラーの 2 ステップ取得
OSV REST API の `/v1/querybatch` は `{id, modified}` しか返さないため、完全情報の取得は 2 ステップ:
1. `POST /v1/querybatch` → 脆弱性 ID と最終更新日時の一覧を取得
2. cutoff（`OSV_DAYS` 日前）より新しいものだけ `GET /v1/vulns/{id}` で完全情報を取得

### OSV クローラーの対象エコシステム
`POPULAR_PACKAGES` dict に定義された 10 エコシステムの主要パッケージを監視対象とする:
PyPI / npm / Go / Maven / RubyGems / NuGet / crates.io / Packagist / Hex / **Pub**（Dart / Flutter）

### OSV クローラーの DB 保護
- Neon 無料プランは長時間トランザクションがタイムアウトする → `_COMMIT_EVERY = 50` 件ごとに定期コミット
- `(osv_id, ecosystem, package_name)` の複合ユニーク制約あり → Upsert 前にリスト内の重複を除去
- `OSV_RETENTION_DAYS`（デフォルト 180 日）を超えたレコードはクロール毎に自動削除

### JVN クローラーの XML パース
MyJVN API（`https://jvndb.jvn.jp/myjvn`）は RDF/RSS 1.0 形式で返す。XML 名前空間に注意:
- JVNDB ID: `<sec:identifier>` 要素（`dc:identifier` ではない）
- 影響製品: `<sec:cpe vendor="..." product="...">` 要素（`sec:affected` ではない）
- CVE 参照: `<sec:references source="CVE" ...>` の `source` 属性（`type` 属性ではない）
- `<title>` / `<link>` は RSS 既定名前空間（`rss:`）に属するため `rss:title` / `rss:link` で検索
- defusedxml を使用して XXE / Billion-laughs 攻撃を防止

### lifespan の scan_results テーブル削除はベストエフォート
旧スキャン機能廃止に伴い、起動時に `DROP TABLE IF EXISTS scan_results` を実行しているが、  
DDL 競合や権限不足で失敗してもサービスを止めないよう `try/except SQLAlchemyError` で囲んである。

### /admin/*-crawl はバックグラウンド実行（202 即時返却）
`/admin/crawl`・`/admin/osv-crawl`・`/admin/jvn-crawl` は即座に 202 Accepted を返し、
`threading.Thread(daemon=True)` でバックグラウンド実行する。
Render Free プランのリクエストタイムアウト（~30s）で OSV クロール（~150s）が
502 になる問題を回避するための設計。結果は `/api/crawler-logs` で確認する。
OSV・JVN は `?days=N` クエリパラメータで取得対象日数を指定可能（初回バックフィル用）。

### Render Free プランのスリープ対策
Render Free プランはアクセスがないと 15 分でスリープし APScheduler が発火しない。  
`.github/workflows/daily-crawl.yml` で GitHub Actions cron が毎日 `/admin/crawl`・`/admin/osv-crawl`・`/admin/jvn-crawl` を叩いて補完している。  
APScheduler と GitHub Actions の二重クロールは発生しない（Render がスリープ中は APScheduler が動かない）。

### pytest フィクスチャ構成
- `setup_test_db`（`scope="session"`）: テスト DB のテーブル作成・削除
- `clean_db`（`autouse=True`）: 各テスト後に全レコード削除
- `client`: `dependency_overrides` でテスト DB を注入した `TestClient`
- `db_session`: テスト用 SQLAlchemy セッション

### Windows でのテスト DB ファイルロック
```python
# teardown 時は dispose() でコネクションを解放してからファイル削除
test_engine.dispose()
try:
    if os.path.exists("test.db"):
        os.remove("test.db")
except OSError:
    pass
```

---

## CI/CD（GitHub Actions）

### CI（ci.yml）
PR 作成・main/develop へのプッシュで自動実行。

1. `ruff check app/ tests/` — Linting
2. `mypy app/ --ignore-missing-imports` — 型チェック
3. `pytest --cov=app --cov-fail-under=90` — テスト（カバレッジ 90% 未満で失敗）
4. `htmlcov/` を GitHub Actions Artifact として 30 日間保持（Python 3.11 のみ）
5. Python 3.10 / 3.11 の matrix で並列実行

### CD（deploy.yml）
main ブランチへのマージ後に自動実行。

- Render デプロイ: GitHub Secrets の `RENDER_DEPLOY_HOOK_URL` に Deploy Hook URL を設定（未設定時はスキップ）
- Vercel デプロイ: `VERCEL_TOKEN` / `VERCEL_ORG_ID` / `VERCEL_PROJECT_ID` を設定（未設定時はスキップ）
- **注意:** `secrets` コンテキストは `if` 条件式で直接参照できないため、`run` ブロック内のシェル分岐で判定する

### 毎日クロール（daily-crawl.yml）
Render Free プランのスリープ問題を回避するため、GitHub Actions から直接 API を叩いてクロールを強制実行する。
**単一 cron（`5 19 * * *` / JST 翌 04:05）で全 3 クローラーを順次実行する構成。**
GitHub Actions 無料プランでは複数 cron の発火が不安定なため、単一 cron に統合した。

| 実行順 | ジョブ | 対象 | 備考 |
|--------|--------|------|------|
| 1 | `wake-up` | Render 起動 | ヘルスチェックでスリープ解除 |
| 2 | `crawl-kev` | `POST /admin/crawl` | KEV フィード取得 |
| 3 | `crawl-osv` | `POST /admin/osv-crawl` | OSV 脆弱性取得（timeout 600s） |
| 4 | `crawl-jvn` | `POST /admin/jvn-crawl` | JVN 脆弱性取得（timeout 600s） |

- 各ジョブは `always()` で前段の失敗に関わらず実行される（`wake-up` 成功が前提）
- `workflow_dispatch` で手動実行可能（`target: kev / osv / jvn / all`）

- GitHub Secrets に `API_KEY`（Render 環境変数と同じ値）を設定すること
- `workflow_dispatch` で手動実行も可能（`target: kev / osv / jvn / both / all`）

---

## デプロイ構成

| 役割 | サービス | 備考 |
|------|---------|------|
| **アプリサーバー** | Render（Web Service） | Python 3.11、Free プラン |
| **データベース** | Neon（PostgreSQL 16） | Free プラン、0.5 GB |
| **ダッシュボード** | Vercel | React（`dashboard/` ディレクトリ） |
| **CI/CD** | GitHub Actions | PR → CI → Merge → 自動デプロイ |

### Render の設定
- **Build Command:** `pip install -r requirements.txt`
- **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- **Environment Variables:** `DATABASE_URL`, `API_KEY`, `ENVIRONMENT=production`, `SLACK_WEBHOOK_URL`（任意）

### GitHub Secrets の設定

| Secret 名 | 説明 |
|-----------|------|
| `RENDER_DEPLOY_HOOK_URL` | Render の Deploy Hook URL（CD 用） |
| `API_KEY` | Render に設定した API キーと同じ値（daily-crawl.yml 用） |

---

## 環境ファイル

| ファイル | 用途 | Git 管理 |
|---------|------|---------|
| `.env.example` | テンプレート（値なし） | ✅ 追跡 |
| `.env.development` | ローカル開発（SQLite） | ❌ gitignore |
| `.env.production` | 本番設定（Neon PostgreSQL） | ❌ gitignore |
| `.env.test` | テスト実行用 | ❌ gitignore |

---

## リファクタリング方針

- 元の機能・仕様を変更してはいけません。
- 外部から見える振る舞い（API・入出力）は変えないでください。
- 内部構造・設計・可読性・保守性を改善してください。

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
# → GitHub 上で Pull Request を作成

# 4. CI（ruff・mypy・pytest）が通ったら main へマージ
# → 自動デプロイが走る
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
