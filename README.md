# Cyberattack Info API

[![CI](https://github.com/baby-feelings/cyberattack_info_api/actions/workflows/ci.yml/badge.svg)](https://github.com/baby-feelings/cyberattack_info_api/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-97%25-brightgreen)](https://github.com/baby-feelings/cyberattack_info_api/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11-blue)](https://www.python.org/)

米 CISA の [Known Exploited Vulnerabilities (KEV) Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) を定期収集し、REST API として配信するプラットフォームです。  
Claude Code や CI/CD ツールから「今まさに悪用されているサイバー脅威」をリアルタイムに取得するために最適化されています。

---

## 機能

| 機能 | 説明 |
|------|------|
| **自動クローラー** | 毎日 AM 4:00 (JST) に CISA KEV フィードを取得・Upsert |
| **一覧取得 API** | ページネーション・キーワード検索・フィルタリング対応 |
| **直近脅威 API** | 過去 N 日以内に追加された脆弱性を即座に取得 |
| **CVE 個別取得** | CVE ID を指定して脆弱性詳細を 1 件取得 |
| **統計 API** | ベンダー別ランキング・月別トレンドを集計 |
| **ライブラリスキャン** | `requirements.txt` / `package.json` の脆弱性を OSV + KEV で診断 |
| **スキャン履歴** | 過去のスキャン結果を保存・参照 |
| **Slack 通知** | 新規 CVE 追加時・エラー時に Slack へ自動通知 |
| **手動クロール** | `POST /admin/crawl` でスケジュール外に即時取得 |
| **API キー認証** | `X-API-KEY` ヘッダーによるシンプルな固定キー認証 |
| **ヘルスチェック** | DB 接続確認付きの死活監視エンドポイント |

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

### GET /api/vulnerabilities — 脆弱性一覧取得

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

### GET /api/vulnerabilities/stats — 統計情報

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

### POST /api/scan — パッケージ脆弱性スキャン

```bash
curl -X POST -H "X-API-KEY: your-key" -H "Content-Type: application/json" \
  -d '{"packages":[{"name":"fastapi","version":"0.115.6"},{"name":"httpx"}]}' \
  "http://localhost:8000/api/scan"
```

### POST /api/scan/requirements — requirements.txt スキャン

```bash
curl -X POST -H "X-API-KEY: your-key" -H "Content-Type: text/plain" \
  --data-binary @requirements.txt \
  "http://localhost:8000/api/scan/requirements"
```

### POST /api/scan/package-json — npm パッケージスキャン

```bash
curl -X POST -H "X-API-KEY: your-key" -H "Content-Type: text/plain" \
  --data-binary @package.json \
  "http://localhost:8000/api/scan/package-json"
```

### GET /api/scan/history — スキャン履歴一覧

```bash
curl -H "X-API-KEY: your-key" \
  "http://localhost:8000/api/scan/history?limit=10"
```

### GET /api/scan/history/{id} — スキャン結果詳細

```bash
curl -H "X-API-KEY: your-key" \
  "http://localhost:8000/api/scan/history/1"
```

### POST /admin/crawl — 手動クロール（即時取得）

```bash
curl -X POST -H "X-API-KEY: your-key" \
  "http://localhost:8000/admin/crawl"
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
pytest tests/test_scan.py -v
pytest tests/test_notifications.py -v

# HTML カバレッジレポートを生成して開く
pytest
start htmlcov/index.html  # Mac/Linux: open htmlcov/index.html
```

**テスト結果（最新）:** 80 テスト / カバレッジ 97%

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
│   ├── models.py          # ORM モデル (vulnerabilities / scan_results テーブル)
│   ├── schemas.py         # Pydantic スキーマ (リクエスト/レスポンス)
│   ├── auth.py            # X-API-KEY 認証
│   ├── cron.py            # CISA KEV クローラー (Upsert ロジック)
│   ├── notifications.py   # Slack Webhook 通知
│   └── routers/
│       ├── vulnerabilities.py  # /api/vulnerabilities エンドポイント
│       └── scan.py             # /api/scan エンドポイント
├── tests/
│   ├── conftest.py           # テスト用フィクスチャ (SQLite テスト DB)
│   ├── test_api.py           # API エンドポイントテスト
│   ├── test_cron.py          # クローラーユニットテスト
│   ├── test_scan.py          # スキャン API テスト
│   └── test_notifications.py # Slack 通知テスト
├── .github/
│   └── workflows/
│       ├── ci.yml       # CI: lint + type check + test (PR 時に自動実行)
│       └── deploy.yml   # CD: Render デプロイ (main マージ時に自動実行)
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
| `RENDER_DEPLOY_HOOK_URL` | Render の Deploy Hook URL |

設定後、`main` ブランチへのマージで自動デプロイが走ります。

---

## 環境変数一覧

| 変数名 | 必須 | 説明 |
|--------|------|------|
| `DATABASE_URL` | ✅ | DB 接続文字列（SQLite or PostgreSQL） |
| `API_KEY` | ✅ | X-API-KEY 認証キー（十分に長いランダム文字列） |
| `ENVIRONMENT` | - | `development` / `production`（デフォルト: `development`） |
| `CISA_KEV_URL` | - | CISA KEV フィード URL（通常は変更不要） |
| `CRON_HOUR_UTC` | - | クローラー実行時刻（時・UTC）（デフォルト: `19`） |
| `CRON_MINUTE_UTC` | - | クローラー実行時刻（分・UTC）（デフォルト: `0`） |
| `SLACK_WEBHOOK_URL` | - | Slack Incoming Webhook URL（未設定時は通知スキップ） |

---

## Slack 通知の設定

1. [Slack App Directory](https://your-workspace.slack.com/apps/A0F7XDUAZ-incoming-webhooks) で「Incoming WebHooks」を追加
2. 通知先チャンネルを選択して Webhook URL を取得
3. Render の環境変数 `SLACK_WEBHOOK_URL` に設定

新規 CVE が追加された日のクロール完了後、および API エラー発生時に通知が届きます。

---

## Claude Code での活用例

```bash
# 直近 30 日の脅威を分析
curl -s -H "X-API-KEY: $API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/vulnerabilities/recent?days=30" \
  | claude -p "Python プロジェクトに影響する脆弱性を優先度順に教えて"

# プロジェクトの依存ライブラリを一括スキャン
curl -s -X POST -H "X-API-KEY: $API_KEY" -H "Content-Type: text/plain" \
  --data-binary @requirements.txt \
  "https://cyberattack-info-api.onrender.com/api/scan/requirements"
```

---

## ライセンス

MIT
