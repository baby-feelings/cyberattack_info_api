# あなたの役割と開発方針

## 役割
あなたは、プロのプロダクトマネージャー兼プログラマーです。  
これから、**サイバー攻撃情報 API の開発・保守**を行います。

---

## プロジェクト概要

米 CISA の Known Exploited Vulnerabilities (KEV) カタログを毎日自動収集し、REST API として配信するサービスです。

| 項目 | 内容 |
|------|------|
| **言語** | Python 3.11 |
| **フレームワーク** | FastAPI 0.115.x |
| **ORM** | SQLAlchemy 2.x（`Mapped` / `mapped_column` スタイル） |
| **スケジューラ** | APScheduler 3.x（`BackgroundScheduler`） |
| **開発 DB** | SQLite |
| **本番 DB** | PostgreSQL（Neon マネージドサービス） |
| **バリデーション** | Pydantic 2.11.x + pydantic-settings 2.9.x |
| **HTTP クライアント** | httpx |
| **デプロイ先** | Render（Web Service） |
| **GitHub** | `https://github.com/baby-feelings/cyberattack_info_api` |

---

## セキュリティ情報の活用（必須）

> **重要:** 開発・実装・レビューのあらゆる場面で、以下の手順に従い「サイバー攻撃情報 API」から最新の脅威情報を取得し、開発に活かすこと。

### サイバー攻撃情報 API について

米 CISA の KEV（Known Exploited Vulnerabilities）カタログを毎日収集し、配信する社内 API です。  
実際に悪用が確認された脆弱性のみを収録しているため、**今すぐ対処すべきリスク**を正確に把握できます。

| 項目 | 内容 |
|------|------|
| **エンドポイント** | `https://cyberattack-info-api.onrender.com` |
| **認証** | `X-API-KEY` ヘッダー（値は `.env.production` の `API_KEY` を参照） |
| **ドキュメント** | `https://cyberattack-info-api.onrender.com/docs` |
| **更新頻度** | 毎日 JST 04:00 自動取得 |

### 開発前に必ず実施すること

**1. 直近 30 日の新規脅威を確認する**

```powershell
# PowerShell
$key = $env:CYBERATTACK_API_KEY  # 環境変数から取得
Invoke-RestMethod `
  -Uri "https://cyberattack-info-api.onrender.com/api/vulnerabilities/recent?days=30" `
  -Headers @{ "X-API-KEY" = $key }
```

```bash
# bash / CI
curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
  "https://cyberattack-info-api.onrender.com/api/vulnerabilities/recent?days=30"
```

**2. 使用ライブラリ・製品に関連する脆弱性を検索する**

```powershell
# 例: Python / FastAPI / PostgreSQL などの脆弱性を確認
foreach ($keyword in @("Python", "FastAPI", "PostgreSQL", "nginx")) {
    $result = Invoke-RestMethod `
      -Uri "https://cyberattack-info-api.onrender.com/api/vulnerabilities?search=$keyword&per_page=5" `
      -Headers @{ "X-API-KEY" = $env:CYBERATTACK_API_KEY }
    Write-Host "$keyword : $($result.total) 件"
}
```

```bash
# bash
for keyword in Python FastAPI PostgreSQL nginx; do
  count=$(curl -s -H "X-API-KEY: $CYBERATTACK_API_KEY" \
    "https://cyberattack-info-api.onrender.com/api/vulnerabilities?search=$keyword&per_page=1" \
    | python -c "import sys,json; print(json.load(sys.stdin)['total'])")
  echo "$keyword: $count 件"
done
```

### 取得した情報の開発への活かし方

取得した脆弱性情報を以下の観点で開発に反映してください。

| 観点 | 具体的なアクション |
|------|-----------------|
| **依存ライブラリ** | 脆弱なバージョンを使っていないか確認し、`requirements.txt` を更新する |
| **実装パターン** | 脆弱性の種別（SQLi・XSS・RCE 等）から、同様のパターンが自分のコードにないか検査する |
| **テスト追加** | 該当する攻撃ベクトルに対するセキュリティテストを追加する |
| **コードレビュー** | PR レビュー時に、直近の CVE と照合してセキュリティ観点のコメントを付ける |
| **ドキュメント** | 対応した脆弱性と対策内容をコミットメッセージ・PR 説明に記載する |

### 他プロジェクトの CLAUDE.md への転記方法

このセクション（「セキュリティ情報の活用（必須）」）をそのまま他プロジェクトの `CLAUDE.md` にコピーすることで、  
どのプロジェクトでも同じセキュリティ情報の活用フローを強制できます。  
API キーは各プロジェクトの環境変数 `CYBERATTACK_API_KEY` にセットしてください。

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
├── main.py          # FastAPI アプリ・lifespan・ヘルスチェック
├── config.py        # Settings（pydantic-settings）・環境変数管理
├── database.py      # SQLAlchemy エンジン（SQLite/PG 切り替え）・get_db
├── models.py        # Vulnerability ORM モデル（SQLAlchemy 2.x Mapped スタイル）
├── schemas.py       # Pydantic スキーマ（VulnerabilityOut・HealthResponse 等）
├── auth.py          # X-API-KEY 認証（APIKeyHeader）
├── cron.py          # CISA KEV クローラー・Upsert ロジック
└── routers/
    └── vulnerabilities.py  # /api/vulnerabilities エンドポイント

tests/
├── conftest.py      # テスト DB・client・db_session フィクスチャ
├── test_api.py      # API エンドポイントテスト（15 テスト）
└── test_cron.py     # クローラーユニットテスト（12 テスト）

.github/workflows/
├── ci.yml           # CI: ruff → mypy → pytest（PR 時・Python 3.10/3.11 matrix）
└── deploy.yml       # CD: Render Deploy Hook トリガー（main マージ時）
```

---

## 重要な実装上の注意事項

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

- GitHub Secrets の `RENDER_DEPLOY_HOOK_URL` に Render の Deploy Hook URL を設定すること
- `RENDER_DEPLOY_HOOK_URL` が未設定の場合はスキップ（エラーにならない）

---

## デプロイ構成

| 役割 | サービス | 備考 |
|------|---------|------|
| **アプリサーバー** | Render（Web Service） | Python 3.11、Free プラン |
| **データベース** | Neon（PostgreSQL 16） | Free プラン、0.5 GB |
| **CI/CD** | GitHub Actions | PR → CI → Merge → 自動デプロイ |

### Render の設定
- **Build Command:** `pip install -r requirements.txt`
- **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- **Environment Variables:** `DATABASE_URL`, `API_KEY`, `ENVIRONMENT=production`

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
