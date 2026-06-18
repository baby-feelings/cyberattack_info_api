# Cyberattack Info API

[![CI](https://github.com/baby-feelings/cyberattack_info_api/actions/workflows/ci.yml/badge.svg)](https://github.com/baby-feelings/cyberattack_info_api/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-99%25-brightgreen)](https://github.com/baby-feelings/cyberattack_info_api/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11-blue)](https://www.python.org/)

米 CISA の [Known Exploited Vulnerabilities (KEV) Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)・[OSV (Open Source Vulnerabilities)](https://osv.dev/)・[JVN (Japan Vulnerability Notes)](https://jvndb.jvn.jp/) を定期収集し、REST API として配信するプラットフォームです。  
Claude Code や CI/CD ツールから「今まさに悪用されているサイバー脅威」をリアルタイムに取得するために最適化されています。

---

## 機能

| 機能 | 説明 |
|------|------|
| **CISA KEV 自動クローラー** | 毎日 JST 04:05 に KEV → OSV → JVN を順次実行（CISA KEV フィード取得・Upsert） |
| **OSV 自動クローラー** | 同上（OSV API から 10 エコシステムの主要パッケージの脆弱性を取得・Upsert） |
| **JVN 自動クローラー** | 同上（MyJVN API から国内脆弱性を取得・Upsert） |
| **OSV 古いデータ自動削除** | 180 日以上前のレコードをクロール時に自動削除（DB 容量管理） |
| **Render スリープ対策** | GitHub Actions cron で毎日クロールを強制実行（Free プラン対応） |
| **一覧取得 API** | ページネーション・キーワード検索・フィルタリング対応（KEV / OSV / JVN） |
| **直近脅威 API** | 過去 N 日以内に追加された脆弱性を即座に取得（KEV） |
| **CVE 個別取得** | CVE ID を指定して脆弱性詳細を 1 件取得（KEV） |
| **統計 API** | ベンダー別ランキング・月別トレンド・重要度別集計（KEV / OSV / JVN） |
| **クローラー実行ログ API** | KEV / OSV / JVN クローラーの実行履歴（成否・件数・所要時間）を取得 |
| **Slack 通知** | 新規追加・更新時・エラー時に Slack へ自動通知（KEV / OSV / JVN） |
| **手動クロール** | `POST /admin/crawl` / `POST /admin/osv-crawl` / `POST /admin/jvn-crawl` で即時取得 |
| **API キー認証** | `X-API-KEY` ヘッダーによるシンプルな固定キー認証 |
| **ヘルスチェック** | DB 接続確認付きの死活監視エンドポイント |
| **React ダッシュボード** | CISA KEV・OSV（Pub 含む 10 エコシステム対応）・JVN の 3 セクション構成（Vercel デプロイ） |

---

## クイックスタート

### 1. リポジトリのクローン

```bash
git clone https://github.com/baby-feelings/cyberattack_info_api.git
cd cyberattack_info_api
```

### 2. 仮想環境のセットアップ

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
```

### 3. 環境変数の設定

```bash
cp .env.example .env.development
# .env.development を編集して DATABASE_URL と API_KEY を設定する
```

**開発環境（SQLite）の場合:**
```env
DATABASE_URL=sqlite:///./cyberattack_dev.db
API_KEY=your-secret-key-here
ENVIRONMENT=development
```

**本番環境（PostgreSQL - Neon）の場合:**
```env
DATABASE_URL=postgresql://user:password@ep-xxxx.ap-southeast-1.aws.neon.tech/neondb?sslmode=require
API_KEY=your-very-secret-key-here
ENVIRONMENT=production
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...  # 任意
```

### 4. 開発サーバーの起動

```bash
uvicorn app.main:app --reload --env-file .env.development
```

Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## API リファレンス

全エンドポイント（`/health` を除く）で `X-API-KEY` ヘッダーが必要です。

### GET /api/vulnerabilities — 脆弱性一覧取得（CISA KEV）

```bash
curl -H "X-API-KEY: your-key" \
  "http://localhost:8000/api/vulnerabilities?page=1&per_page=10&search=Microsoft"
```

| パラメータ | 型 | デフォルト | 説明 |
|-----------|-----|-----------|------|
| `page` | int | 1 | ページ番号 |
| `per_page` | int | 50 | 1ページあたりの件数（最大 500） |
| `search` | string | - | ベンダー名・製品名の部分一致検索 |
| `vendor` | string | - | ベンダー名の完全一致フィルタ |
| `product` | string | - | 製品名の部分一致フィルタ |

### GET /api/vulnerabilities/{cve_id} — CVE 個別取得

```bash
curl -H "X-API-KEY: your-key" \
  "http://localhost:8000/api/vulnerabilities/CVE-2021-44228"
```

### GET /api/vulnerabilities/recent — 直近の脅威取得

```bash
curl -H "X-API-KEY: your-key" \
  "http://localhost:8000/api/vulnerabilities/recent?days=30"
```

### GET /api/vulnerabilities/stats — 統計情報（CISA KEV）

```bash
curl -H "X-API-KEY: your-key" \
  "http://localhost:8000/api/vulnerabilities/stats"
```

**レスポンス例:**
```json
{
  "total_vulnerabilities": 1619,
  "top_vendors": [
    { "vendor_project": "Microsoft", "count": 312 }
  ],
  "monthly_trend": [
    { "year_month": "2026-05", "count": 23 }
  ]
}
```

### GET /api/osv — OSV 脆弱性一覧取得

10 エコシステム（PyPI / npm / Go / Maven / RubyGems / NuGet / crates.io / Packagist / Hex / Pub）の直近 30 日の脆弱性一覧を取得します。

```bash
curl -H "X-API-KEY: your-key" \
  "http://localhost:8000/api/osv?ecosystem=PyPI&severity=HIGH&per_page=20"
```

| パラメータ | 型 | デフォルト | 説明 |
|-----------|-----|-----------|------|
| `page` | int | 1 | ページ番号 |
| `per_page` | int | 50 | 1ページあたりの件数（最大 500） |
| `ecosystem` | string | - | エコシステム名でフィルタ（例: `PyPI` / `Pub`） |
| `severity` | string | - | 重要度でフィルタ（`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`） |
| `search` | string | - | パッケージ名の部分一致検索 |
| `sort_by` | string | `modified` | ソート基準（`modified` / `cvss`） |

### GET /api/osv/stats — OSV 統計情報

```bash
curl -H "X-API-KEY: your-key" \
  "http://localhost:8000/api/osv/stats"
```

### GET /api/jvn — JVN 脆弱性一覧取得

MyJVN API から収集した直近 30 日の JVN 脆弱性一覧を取得します。

```bash
curl -H "X-API-KEY: your-key" \
  "http://localhost:8000/api/jvn?severity=High&sort_by=cvss"
```

| パラメータ | 型 | デフォルト | 説明 |
|-----------|-----|-----------|------|
| `page` | int | 1 | ページ番号 |
| `per_page` | int | 50 | 1ページあたりの件数（最大 500） |
| `severity` | string | - | 重要度でフィルタ（`High` / `Medium` / `Low`） |
| `search` | string | - | JVNDB ID・タイトル・概要の部分一致検索 |
| `sort_by` | string | `modified` | ソート基準（`modified` / `cvss`） |
| `days` | int | 30 | 取得対象の直近日数 |

**レスポンス例:**
```json
{
  "total": 129,
  "page": 1,
  "per_page": 50,
  "data": [
    {
      "jvndb_id": "JVNDB-2026-020172",
      "title": "CISA ICS Advisory（2026年06月16日）",
      "overview": "...",
      "cve_ids": ["CVE-2026-12345"],
      "severity": "High",
      "cvss_score": 9.8,
      "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "affected_products": [
        { "vendor": "（複数のベンダ）", "product": "（複数の製品）", "cpe": "cpe:/a:misc:multiple_vendors" }
      ],
      "references": [],
      "jvn_url": "https://jvndb.jvn.jp/ja/contents/2026/JVNDB-2026-020172.html",
      "date_published": "2026-06-18T11:35:05+09:00",
      "date_last_modified": "2026-06-18T11:35:05+09:00"
    }
  ]
}
```

### GET /api/jvn/stats — JVN 統計情報

```bash
curl -H "X-API-KEY: your-key" \
  "http://localhost:8000/api/jvn/stats"
```

**レスポンス例:**
```json
{
  "total": 129,
  "severities": [
    { "severity": "High", "count": 45 },
    { "severity": "Medium", "count": 62 },
    { "severity": "Low", "count": 22 }
  ],
  "monthly_trend": [
    { "year_month": "2026-06", "count": 129 }
  ]
}
```

### GET /api/crawler-logs — クローラー実行ログ一覧

KEV / OSV / JVN クローラーの実行履歴（成否・件数・所要時間）を新しい順に返します。

```bash
curl -H "X-API-KEY: your-key" \
  "http://localhost:8000/api/crawler-logs?limit=10"

# JVN のみ絞り込み
curl -H "X-API-KEY: your-key" \
  "http://localhost:8000/api/crawler-logs?crawler_type=JVN"

# エラーのみ絞り込み
curl -H "X-API-KEY: your-key" \
  "http://localhost:8000/api/crawler-logs?status=error"
```

| パラメータ | 型 | デフォルト | 説明 |
|-----------|-----|-----------|------|
| `crawler_type` | string | - | `KEV` / `OSV` / `JVN`（省略時は全種別） |
| `status` | string | - | `success` / `error`（省略時は両方） |
| `limit` | int | 30 | 取得件数（最大 100） |

### POST /admin/crawl — KEV 手動クロール（即時取得）

```bash
curl -X POST -H "X-API-KEY: your-key" \
  "http://localhost:8000/admin/crawl"
```

### POST /admin/osv-crawl — OSV 手動クロール（即時取得）

```bash
curl -X POST -H "X-API-KEY: your-key" \
  "http://localhost:8000/admin/osv-crawl"
```

### POST /admin/jvn-crawl — JVN 手動クロール（即時取得）

```bash
curl -X POST -H "X-API-KEY: your-key" \
  "http://localhost:8000/admin/jvn-crawl"
```

### GET /health — ヘルスチェック（認証不要）

```bash
curl http://localhost:8000/health
```

**レスポンス例:**
```json
{
  "status": "ok",
  "environment": "production",
  "db_connected": true
}
```

---

## テストの実行

```bash
# 全テストを実行（カバレッジ付き）
pytest

# 特定のテストファイルのみ実行
pytest tests/test_api.py -v
pytest tests/test_osv.py -v
pytest tests/test_jvn.py -v
pytest tests/test_notifications.py -v

# HTML カバレッジレポートを生成して開く
pytest
start htmlcov/index.html  # Mac/Linux: open htmlcov/index.html
```

**テスト結果（最新）:** 180 テスト / カバレッジ 99%

---

## 静的解析・型チェック

```bash
# Linting (ruff)
ruff check app/ tests/

# 型チェック (mypy)
mypy app/ --ignore-missing-imports
```

---

## プロジェクト構成

```
cyberattack_info_api/
├── app/
│   ├── main.py            # FastAPI アプリ本体・APScheduler 設定
│   ├── config.py          # 環境変数・設定管理 (pydantic-settings)
│   ├── database.py        # SQLAlchemy エンジン・セッション (SQLite / PostgreSQL 共用)
│   ├── models.py          # ORM モデル (Vulnerability / OsvVulnerability / JvnVulnerability / CrawlerLog)
│   ├── schemas.py         # Pydantic スキーマ (リクエスト/レスポンス)
│   ├── auth.py            # X-API-KEY 認証
│   ├── cron.py            # CISA KEV クローラー (Upsert ロジック・Slack 通知)
│   ├── cron_osv.py        # OSV クローラー (REST API 方式・Upsert・Slack 通知)
│   ├── cron_jvn.py        # JVN クローラー (MyJVN API / RDF-RSS・Upsert・Slack 通知)
│   ├── crawler_log.py     # クローラーログ書き込みユーティリティ
│   ├── notifications.py   # Slack Webhook 通知（KEV・OSV・JVN 対応）
│   └── routers/
│       ├── vulnerabilities.py  # /api/vulnerabilities エンドポイント
│       ├── osv.py              # /api/osv エンドポイント
│       ├── jvn.py              # /api/jvn エンドポイント
│       └── crawler_logs.py     # /api/crawler-logs エンドポイント
├── tests/
│   ├── conftest.py              # テスト用フィクスチャ (SQLite テスト DB)
│   ├── test_api.py              # KEV API エンドポイントテスト
│   ├── test_cron.py             # KEV クローラーユニットテスト
│   ├── test_crawler_logs.py     # クローラーログ API テスト
│   ├── test_database.py         # DB エンジン・セッションテスト
│   ├── test_osv.py              # OSV API・クローラーテスト
│   ├── test_jvn.py              # JVN API・クローラーテスト
│   └── test_notifications.py    # Slack 通知テスト（KEV・OSV・JVN 対応）
├── dashboard/               # Vercel デプロイの React ダッシュボード（KEV・OSV（Pub 含む 10 エコシステム）・JVN）
├── .github/
│   └── workflows/
│       ├── ci.yml           # CI: lint + type check + test (PR 時に自動実行)
│       ├── deploy.yml       # CD: Render デプロイ (main マージ時に自動実行)
│       └── daily-crawl.yml  # 毎日クロール (単一 cron UTC 19:05 で KEV → OSV → JVN 順次実行)
├── .env.example         # 環境変数テンプレート
├── .python-version      # Python バージョン固定 (3.11)
├── requirements.txt     # 本番依存パッケージ
├── requirements-dev.txt # 開発・テスト依存パッケージ
├── pyproject.toml       # ruff / mypy / pytest 設定
└── CLAUDE.md            # Claude Code 向け開発ガイド
```

---

## デプロイ（Render + Neon）

### Step 1: Neon で PostgreSQL を作成

1. [Neon](https://neon.tech) でアカウント作成・プロジェクト作成
2. **Project name:** `cyberattack-info-api`、**Postgres version:** `16`、**Region:** `Singapore`
3. 接続文字列（`postgresql://...`）をコピー

### Step 2: Render で Web Service を作成

1. [Render](https://render.com) で `New > Web Service` を作成
2. このリポジトリを接続
3. 以下を設定:
   - **Runtime:** Python 3
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
4. 環境変数を設定:

   | 変数名 | 値 |
   |--------|-----|
   | `DATABASE_URL` | Neon の接続文字列 |
   | `API_KEY` | ランダムな秘密キー（`openssl rand -hex 32`） |
   | `ENVIRONMENT` | `production` |
   | `SLACK_WEBHOOK_URL` | Slack Webhook URL（任意） |

5. **Deploy Hook URL** を取得 → GitHub Secrets の `RENDER_DEPLOY_HOOK_URL` に登録

### Step 3: GitHub Secrets の設定

| Secret 名 | 説明 |
|-----------|------|
| `RENDER_DEPLOY_HOOK_URL` | Render の Deploy Hook URL（CD 用） |
| `API_KEY` | Render に設定した API キーと同じ値（daily-crawl.yml 用） |

設定後、`main` ブランチへのマージで自動デプロイが走ります。

---

## 環境変数一覧

| 変数名 | 必須 | 説明 |
|--------|------|------|
| `DATABASE_URL` | ✅ | DB 接続文字列（SQLite or PostgreSQL） |
| `API_KEY` | ✅ | X-API-KEY 認証キー（十分に長いランダム文字列） |
| `ENVIRONMENT` | - | `development` / `production`（デフォルト: `development`） |
| `CISA_KEV_URL` | - | CISA KEV フィード URL（通常は変更不要） |
| `CRON_HOUR_UTC` | - | KEV クローラー実行時刻（時・UTC）（デフォルト: `19`） |
| `CRON_MINUTE_UTC` | - | KEV クローラー実行時刻（分・UTC）（デフォルト: `0`） |
| `OSV_DAYS` | - | OSV 取得対象の直近日数（デフォルト: `30`） |
| `OSV_RETENTION_DAYS` | - | OSV データ保持期間（日数・デフォルト: `180`） |
| `JVN_DAYS` | - | JVN 取得対象の直近日数（デフォルト: `30`） |
| `SLACK_WEBHOOK_URL` | - | Slack Incoming Webhook URL（未設定時は通知スキップ） |

---

## Slack 通知の設定

1. [Slack App Directory](https://your-workspace.slack.com/apps/A0F7XDUAZ-incoming-webhooks) で「Incoming WebHooks」を追加
2. 通知先チャンネルを選択して Webhook URL を取得
3. Render の環境変数 `SLACK_WEBHOOK_URL` に設定

通知が届くタイミング:

| タイミング | 通知内容 |
|-----------|---------|
| CISA KEV クロール完了（新規追加・更新あり） | `:shield: CISA KEV 更新通知`（新規・更新件数） |
| OSV クロール完了（新規・更新あり） | `:package: OSV 脆弱性データ更新通知`（新規・更新・削除件数） |
| JVN クロール完了（新規・更新あり） | `:jigsaw: JVN 脆弱性データ更新通知`（新規・更新件数） |
| クローラーエラー発生時 | `:warning:` エラー内容（KEV / OSV / JVN それぞれ） |

---

## データ更新スケジュール

| タイミング | 処理 |
|----------|------|
| 毎日 JST 04:05（UTC 19:05）| GitHub Actions 単一 cron で KEV → OSV → JVN を順次実行 |
| アプリ起動時 | DB テーブルの自動作成 |
| `POST /admin/crawl` 実行時 | KEV 即時取得（スケジュール外） |
| `POST /admin/osv-crawl` 実行時 | OSV 即時取得（スケジュール外） |
| `POST /admin/jvn-crawl` 実行時 | JVN 即時取得（スケジュール外） |

> **Note:** APScheduler（アプリ内スケジューラ）も UTC 19:00 / 20:00 / 21:00 に設定されていますが、  
> Render Free プランのスリープ中は発火しません。GitHub Actions の単一 cron がその補完として機能します。

---

## Claude Code での活用例

```bash
# 直近 30 日の脅威を分析
curl -s -H "X-API-KEY: $API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/vulnerabilities/recent?days=30" \
  | claude -p "Python プロジェクトに影響する脆弱性を優先度順に教えて"

# OSV の高リスク脆弱性を確認
curl -s -H "X-API-KEY: $API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/osv?severity=CRITICAL&ecosystem=PyPI"

# JVN の直近 High 重要度脆弱性を確認
curl -s -H "X-API-KEY: $API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/jvn?severity=High&sort_by=cvss"

# クローラーの最新実行結果を確認
curl -s -H "X-API-KEY: $API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/crawler-logs?limit=5"
```

---

## ライセンス

MIT
