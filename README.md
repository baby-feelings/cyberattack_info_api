# Cyberattack Info API

[![CI](https://github.com/baby-feelings/cyberattack_info_api/actions/workflows/ci.yml/badge.svg)](https://github.com/baby-feelings/cyberattack_info_api/actions/workflows/ci.yml)

米 CISA の [Known Exploited Vulnerabilities (KEV) Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) を定期収集し、REST API として配信するプラットフォームです。  
Claude Code や CI/CD ツールから「今まさに悪用されているサイバー脅威」をリアルタイムに取得するために最適化されています。

---

## 機能

| 機能 | 説明 |
|------|------|
| **自動クローラー** | 毎日 AM 4:00 (JST) に CISA KEV フィードを取得・Upsert |
| **一覧取得 API** | ページネーション・キーワード検索・フィルタリング対応 |
| **直近脅威 API** | 過去 N 日以内に追加された脆弱性を即座に取得 |
| **API キー認証** | `X-API-KEY` ヘッダーによるシンプルな固定キー認証 |

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
cp .env.example .env
# .env を編集して DATABASE_URL と API_KEY を設定する
```

**開発環境（SQLite）の場合:**
```env
DATABASE_URL=sqlite:///./cyberattack_dev.db
API_KEY=your-secret-key-here
ENVIRONMENT=development
```

**本番環境（PostgreSQL - Neon/Supabase）の場合:**
```env
DATABASE_URL=postgresql://user:password@host:5432/dbname
API_KEY=your-very-secret-key-here
ENVIRONMENT=production
```

### 4. 開発サーバーの起動

```bash
uvicorn app.main:app --reload --env-file .env.development
```

Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## API リファレンス

全エンドポイントで `X-API-KEY` ヘッダーが必要です。

### GET /api/vulnerabilities — 脆弱性一覧取得

```bash
curl -H "X-API-KEY: your-key" \
  "http://localhost:8000/api/vulnerabilities?page=1&per_page=10&search=Microsoft"
```

**クエリパラメータ:**

| パラメータ | 型 | デフォルト | 説明 |
|-----------|-----|-----------|------|
| `page` | int | 1 | ページ番号 |
| `per_page` | int | 50 | 1ページあたりの件数（最大 500） |
| `search` | string | - | ベンダー名・製品名の部分一致検索 |
| `vendor` | string | - | ベンダー名の完全一致フィルタ |
| `product` | string | - | 製品名の部分一致フィルタ |

**レスポンス例:**
```json
{
  "total": 1205,
  "page": 1,
  "per_page": 2,
  "data": [
    {
      "cve_id": "CVE-2026-12345",
      "vendor_project": "Microsoft",
      "product": "Windows",
      "vulnerability_name": "Remote Code Execution via...",
      "description": "A critical vulnerability allows attackers to...",
      "required_action": "Apply the patch immediately.",
      "date_added": "2026-05-10"
    }
  ]
}
```

### GET /api/vulnerabilities/recent — 直近の脅威取得

Claude Code のコンテキストにそのまま渡すために最適化されたエンドポイントです。

```bash
curl -H "X-API-KEY: your-key" \
  "http://localhost:8000/api/vulnerabilities/recent?days=30"
```

**クエリパラメータ:**

| パラメータ | 型 | デフォルト | 説明 |
|-----------|-----|-----------|------|
| `days` | int | 30 | 過去何日分のデータを取得するか（1〜365） |

**レスポンス:** `VulnerabilityOut` オブジェクトの配列を直接返します。

### GET /health — ヘルスチェック（認証不要）

```bash
curl http://localhost:8000/health
```

---

## テストの実行

```bash
# 全テストを実行（カバレッジ付き）
pytest

# 特定のテストファイルのみ実行
pytest tests/test_api.py -v
pytest tests/test_cron.py -v
```

---

## プロジェクト構成

```
cyberattack_info_api/
├── app/
│   ├── main.py          # FastAPI アプリ本体・スケジューラ設定
│   ├── config.py        # 環境変数・設定管理 (pydantic-settings)
│   ├── database.py      # SQLAlchemy エンジン・セッション管理
│   ├── models.py        # ORM モデル (vulnerabilities テーブル)
│   ├── schemas.py       # Pydantic スキーマ (リクエスト/レスポンス)
│   ├── auth.py          # X-API-KEY 認証
│   ├── cron.py          # CISA KEV クローラー (Upsert ロジック)
│   └── routers/
│       └── vulnerabilities.py  # API エンドポイント定義
├── tests/
│   ├── conftest.py      # テスト用フィクスチャ (SQLite インメモリ DB)
│   ├── test_api.py      # API エンドポイントテスト
│   └── test_cron.py     # クローラーユニットテスト
├── .github/
│   └── workflows/
│       ├── ci.yml       # CI: lint + test (PR 時に自動実行)
│       └── deploy.yml   # CD: Render/Railway デプロイ (main マージ時)
├── .env.example         # 環境変数テンプレート
├── requirements.txt     # 本番依存パッケージ
├── requirements-dev.txt # 開発・テスト依存パッケージ
└── pyproject.toml       # ruff/mypy/pytest 設定
```

---

## デプロイ（Render / Railway）

### Render の場合

1. [Render](https://render.com) で `New Web Service` を作成
2. このリポジトリを接続
3. 以下を設定:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
4. 環境変数（`DATABASE_URL`, `API_KEY`, `ENVIRONMENT=production`）を設定
5. Deploy Hook URL を取得し、GitHub Secrets の `RENDER_DEPLOY_HOOK_URL` に登録

### Neon (PostgreSQL 無料枠) の場合

1. [Neon](https://neon.tech) でデータベースを作成
2. 接続文字列を `DATABASE_URL` として設定

---

## 環境変数一覧

| 変数名 | 必須 | 説明 |
|--------|------|------|
| `DATABASE_URL` | ✅ | DB 接続文字列（SQLite or PostgreSQL） |
| `API_KEY` | ✅ | X-API-KEY 認証キー（十分に長いランダム文字列） |
| `ENVIRONMENT` | - | `development` / `production`（デフォルト: development） |
| `CISA_KEV_URL` | - | CISA KEV フィード URL（通常は変更不要） |
| `CRON_HOUR_UTC` | - | クローラー実行時刻（時、UTC）（デフォルト: 19） |
| `CRON_MINUTE_UTC` | - | クローラー実行時刻（分、UTC）（デフォルト: 0） |

---

## Claude Code での活用例

```bash
# 直近30日の脅威を Claude Code のコンテキストとして取得
curl -s -H "X-API-KEY: $API_KEY" \
  "https://your-api.onrender.com/api/vulnerabilities/recent?days=30" \
  | claude -p "これらの脆弱性のうち、Pythonプロジェクトに影響するものを優先度順に教えて"
```

---

## ライセンス

MIT
