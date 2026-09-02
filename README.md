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
| **CISA KEV 自動クローラー** | 毎日 JST 04:05 に KEV → OSV → JVN → DEPSCAN を順次実行（CISA KEV フィード取得・Upsert） |
| **OSV 自動クローラー** | 同上（OSV API から 10 エコシステムの主要パッケージの脆弱性を取得・Upsert） |
| **JVN 自動クローラー** | 同上（MyJVN API から国内脆弱性を取得・Upsert） |
| **依存ライブラリ脆弱性スキャン（DEPSCAN）** | 同上（GitHub 上の自作アプリ全リポジトリ〈プライベート含む〉のロックファイルを OSV API とリアルタイム照合。新規検知はリポジトリ自身に GitHub Issue も自動起票） |
| **OSV 古いデータ自動削除** | 180 日以上前のレコードをクロール時に自動削除（DB 容量管理） |
| **Render スリープ対策** | GitHub Actions cron で毎日クロールを強制実行（Free プラン対応） |
| **一覧取得 API** | ページネーション・キーワード検索・フィルタリング対応（KEV / OSV / JVN / DEPSCAN） |
| **直近脅威 API** | 過去 N 日以内に追加された脆弱性を即座に取得（KEV） |
| **CVE 個別取得** | CVE ID を指定して脆弱性詳細を 1 件取得（KEV） |
| **統計 API** | ベンダー別ランキング・月別トレンド・重要度別集計（KEV / OSV / JVN / DEPSCAN） |
| **クローラー実行ログ API** | KEV / OSV / JVN / DEPSCAN クローラーの実行履歴（成否・件数・所要時間）を取得 |
| **Slack 通知** | 新規追加・更新時・エラー時に Slack へ自動通知（KEV / OSV / JVN / DEPSCAN） |
| **手動クロール** | `POST /admin/crawl` / `POST /admin/osv-crawl` / `POST /admin/jvn-crawl` / `POST /admin/depscan-crawl`（バックグラウンド 202 即時返却・`?days=N` 対応） |
| **API キー認証** | `X-API-KEY` ヘッダーによるシンプルな固定キー認証 |
| **ヘルスチェック** | DB 接続確認付きの死活監視エンドポイント |
| **React ダッシュボード** | CISA KEV・OSV（Pub 含む 10 エコシステム・180 日表示）・JVN を画面下部固定タブで切り替え表示（Vercel デプロイ） |

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

> **Note:** 本番環境では Swagger UI（`/docs`）と ReDoc（`/redoc`）はセキュリティ上の理由で無効化しています。  
> ローカル開発時は `http://localhost:8000/docs` で OpenAPI ドキュメントを参照できます。

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

**レスポンス例:**
```json
{
  "cve_id": "CVE-2021-44228",
  "vendor_project": "Apache",
  "product": "Log4j",
  "vulnerability_name": "Apache Log4j2 Remote Code Execution Vulnerability",
  "description": "Apache Log4j2 <=2.14.1 JNDI features...",
  "required_action": "For all affected software assets...",
  "date_added": "2021-12-10"
}
```

### GET /api/vulnerabilities/recent — 直近の脅威取得

```bash
curl -H "X-API-KEY: your-key" \
  "http://localhost:8000/api/vulnerabilities/recent?days=30"
```

| パラメータ | 型 | デフォルト | 説明 |
|-----------|-----|-----------|------|
| `days` | int | 30 | 直近何日以内に追加された脆弱性を取得 |

**レスポンス:** `VulnerabilityOut` の配列（ページネーションなし）

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
| `days` | int | 30 | 取得対象の直近日数 |
| `ecosystem` | string | - | エコシステム名でフィルタ（例: `PyPI` / `Pub`） |
| `severity` | string | - | 重要度でフィルタ（`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`） |
| `search` | string | - | パッケージ名の部分一致検索 |
| `sort_by` | string | `modified` | ソート基準（`modified` / `cvss`） |

**レスポンス例:**
```json
{
  "total": 492,
  "page": 1,
  "per_page": 50,
  "data": [
    {
      "osv_id": "GHSA-xxxx-xxxx-xxxx",
      "ecosystem": "PyPI",
      "package_name": "cryptography",
      "aliases": ["CVE-2026-34073"],
      "summary": "DNS name constraints bypass...",
      "details": "...",
      "severity": "HIGH",
      "cvss_score": 7.5,
      "affected_versions": ["<46.0.6"],
      "fixed_versions": ["46.0.6"],
      "references": ["https://github.com/..."],
      "published": "2026-06-01T00:00:00+00:00",
      "modified": "2026-06-15T00:00:00+00:00"
    }
  ]
}
```

### GET /api/osv/stats — OSV 統計情報

```bash
curl -H "X-API-KEY: your-key" \
  "http://localhost:8000/api/osv/stats?days=30"
```

| パラメータ | 型 | デフォルト | 説明 |
|-----------|-----|-----------|------|
| `days` | int | 30 | 集計対象の直近日数 |

**レスポンス例:**
```json
{
  "total": 492,
  "ecosystems": [
    { "ecosystem": "PyPI", "count": 273 },
    { "ecosystem": "npm", "count": 35 }
  ],
  "severities": [
    { "severity": "CRITICAL", "count": 9 },
    { "severity": "HIGH", "count": 67 },
    { "severity": "MEDIUM", "count": 47 },
    { "severity": "LOW", "count": 2 }
  ],
  "monthly_trend": [
    { "year_month": "2026-06", "count": 120 }
  ]
}
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

### GET /api/depscan — 依存ライブラリ脆弱性の検知結果一覧取得

GitHub 上の自作アプリ全リポジトリのロックファイルを OSV API とリアルタイム照合した検知結果を取得します。

```bash
curl -H "X-API-KEY: your-key" \
  "http://localhost:8000/api/depscan?resolved=false&severity=HIGH"
```

| パラメータ | 型 | デフォルト | 説明 |
|-----------|-----|-----------|------|
| `page` | int | 1 | ページ番号 |
| `per_page` | int | 50 | 1ページあたりの件数（最大 200） |
| `repo` | string | - | リポジトリ名で絞り込み（例: `owner/repo`） |
| `ecosystem` | string | - | エコシステムで絞り込み（例: `PyPI` / `npm`） |
| `severity` | string | - | 重要度でフィルタ（`CRITICAL` / `HIGH` / `MEDIUM` / `LOW`） |
| `resolved` | bool | - | 解決状態で絞り込み（省略時は全件） |

**レスポンス例:**
```json
{
  "total": 1,
  "page": 1,
  "per_page": 50,
  "data": [
    {
      "repo_full_name": "baby-feelings/baby_grow",
      "ecosystem": "PyPI",
      "package_name": "cryptography",
      "installed_version": "3.4.7",
      "osv_id": "GHSA-xxxx-xxxx-xxxx",
      "severity": "HIGH",
      "cvss_score": 7.5,
      "summary": "...",
      "fixed_versions": ["3.4.8"],
      "manifest_path": "requirements.txt",
      "detected_at": "2026-08-01T04:05:00+00:00",
      "resolved_at": null
    }
  ]
}
```

### GET /api/depscan/stats — 依存ライブラリ脆弱性の統計情報

未解決の検知結果について、リポジトリ別件数・重要度別件数を返します。

```bash
curl -H "X-API-KEY: your-key" \
  "http://localhost:8000/api/depscan/stats"
```

**レスポンス例:**
```json
{
  "total": 3,
  "repos": [
    { "repo_full_name": "baby-feelings/baby_grow", "count": 2 }
  ],
  "severities": [
    { "severity": "HIGH", "count": 2 },
    { "severity": "MEDIUM", "count": 1 }
  ]
}
```

> **対応が必要なリポジトリの確認方法**
> DEPSCAN の検知結果（対応が必要なリポジトリ・パッケージ）は常に変動するため、本 README には固定リストを記載しない。最新の状態は以下のいずれかで確認する。
> - `GET /api/depscan?resolved=false&severity=CRITICAL`（`severity=HIGH` も併せて確認）で未解決の重大度の高い検知を一覧取得
> - `GET /api/depscan/stats` でリポジトリ別・重要度別の件数サマリーを取得
> - ダッシュボード（Vercel）の DEPSCAN タブ
> - Slack 通知（新規検知時に自動送信される `:rotating_light:` メッセージ）
>
> なお DEPSCAN は対応ロックファイル（10 エコシステム分。一覧は [`app/depscan/parsers/__init__.py`](app/depscan/parsers/__init__.py) の `LOCKFILE_FILENAMES` を参照）が存在するリポジトリのみをスキャン対象とする。ロックファイルが存在しないリポジトリの一覧は API では取得できず、Render の実行ログ（`DEPSCAN: [i/N] scanning ...` の行）でのみ確認できる。

> **検知された脆弱性の実際の修正について**
> DEPSCAN は検知・通知のみを行い、修正コードは生成しない。実際の修正は、DEPSCAN 対象の各リポジトリで有効化した **Dependabot** の更新 PR をマージすることで対応する。マージ運用のポイント:
> - PR マージ前に `mergeable: MERGEABLE` を確認する（CI が無いリポジトリも多い）
> - **メジャーバージョンアップを含む PR は要注意**（例: `typescript` 6.0.3→7.0.2 が `typescript-eslint` との非互換で Vercel ビルドを壊した実例あり）。マージ後は Vercel 等のデプロイ結果を確認する
> - 複数 PR を連続マージすると `package-lock.json` 等の競合で後続 PR がマージ不可になることがある。PR に `@dependabot rebase` とコメントすればリベースされる
> - リベース後、対象パッケージが別 PR で既に修正済みだった場合、Dependabot が PR を自動クローズすることがある（異常ではない）
> - **本番反映方法はリポジトリごとに異なる**。Vercel 連携があるリポジトリはマージ時点で自動デプロイされるが、CI/CD の無いリポジトリ（Firebase Hosting 等）はマージ後にローカルで `pull` し手動でデプロイコマンドを実行するまで反映されない
> - 脆弱性検知時に即座に修正 PR を出す「Dependabot security updates」は、`dependabot.yml` を置くだけでは有効にならず、各リポジトリの `Settings → Code security` で個別に ON にする必要がある

### GET /api/crawler-logs — クローラー実行ログ一覧

KEV / OSV / JVN / DEPSCAN クローラーの実行履歴（成否・件数・所要時間）を新しい順に返します。

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
| `crawler_type` | string | - | `KEV` / `OSV` / `JVN` / `DEPSCAN` / `DEPSOPS`（省略時は全種別） |
| `status` | string | - | `success` / `error`（省略時は両方） |
| `limit` | int | 30 | 取得件数（最大 100） |

**レスポンス例:**
```json
[
  {
    "id": 42,
    "crawler_type": "OSV",
    "status": "success",
    "started_at": "2026-06-22T21:26:07+00:00",
    "finished_at": "2026-06-22T21:28:33+00:00",
    "duration_seconds": 146.1,
    "inserted": 0,
    "updated": 2,
    "deleted": 0,
    "error_message": null
  }
]
```

### POST /admin/crawl — KEV 手動クロール（バックグラウンド実行）

```bash
curl -X POST -H "X-API-KEY: your-key" \
  "http://localhost:8000/admin/crawl"
# → 202 Accepted: {"message": "KEV crawl started in background"}
```

### POST /admin/osv-crawl — OSV 手動クロール（バックグラウンド実行）

```bash
# 通常（デフォルト 30 日分）
curl -X POST -H "X-API-KEY: your-key" \
  "http://localhost:8000/admin/osv-crawl"
# → 202 Accepted: {"message": "OSV crawl started in background (days=default)"}

# 初回バックフィル用（180 日 = 6 ヶ月分）
curl -X POST -H "X-API-KEY: your-key" \
  "http://localhost:8000/admin/osv-crawl?days=180"
```

| パラメータ | 型 | デフォルト | 説明 |
|-----------|-----|-----------|------|
| `days` | int | OSV_DAYS (30) | 取得対象の直近日数（1〜365） |

### POST /admin/jvn-crawl — JVN 手動クロール（バックグラウンド実行）

```bash
# 通常（デフォルト 30 日分）
curl -X POST -H "X-API-KEY: your-key" \
  "http://localhost:8000/admin/jvn-crawl"
# → 202 Accepted: {"message": "JVN crawl started in background (days=default)"}

# 初回バックフィル用（180 日 = 6 ヶ月分）
curl -X POST -H "X-API-KEY: your-key" \
  "http://localhost:8000/admin/jvn-crawl?days=180"
```

| パラメータ | 型 | デフォルト | 説明 |
|-----------|-----|-----------|------|
| `days` | int | JVN_DAYS (30) | 取得対象の直近日数（1〜365） |

### POST /admin/depscan-crawl — 依存ライブラリ脆弱性スキャン手動実行（バックグラウンド実行）

```bash
curl -X POST -H "X-API-KEY: your-key" \
  "http://localhost:8000/admin/depscan-crawl"
# → 202 Accepted: {"message": "Dependency vulnerability scan started in background"}
```

> **Note:** `GITHUB_TOKEN`（GitHub PAT）が未設定の場合、GitHub API への認証が失敗し
> DEPSCAN のみエラー終了します（`/api/crawler-logs` にエラーとして記録されます）。
> 一方 `GITHUB_USERNAME` は必須環境変数のため、未設定だとアプリ全体が起動できません。
>
> **Note:** 新規検知は、検知されたリポジトリ自身に GitHub Issue（タイトル固定、Open な既存
> Issue があればコメント追記）としても自動起票される。ロックファイル読み取り
> （`Contents: Read-only`）に加えて **`Issues: Write`** 権限が必要。権限不足等で
> Issue 作成に失敗しても、ログに警告が記録されるのみで DEPSCAN 自体は成功として扱う。

> **Note:** 手動クロールはバックグラウンドで実行されるため、即座に 202 が返ります。  
> 実行結果は `GET /api/crawler-logs` で確認してください。

### POST /admin/dependabot-ops — Dependabot PR 自動運用（手動トリガーのみ・バックグラウンド実行）

```bash
curl -X POST -H "X-API-KEY: your-key" \
  "http://localhost:8000/admin/dependabot-ops"
# → 202 Accepted: {"message": "Dependabot PR operations started in background"}
```

DEPSCAN が検知した脆弱性は、対象リポジトリで有効化した Dependabot が修正 PR を作成する（
[運用ルール](#post-admindepscan-crawl--依存ライブラリ脆弱性スキャン手動実行バックグラウンド実行)参照）。
このエンドポイントは、その Dependabot PR のうち **安全性の高いものだけを自動マージする**運用層の仕組み。

- DEPSCAN 対象の全リポジトリを走査し、Open な Dependabot PR を判定する
- **自動マージする条件**（すべて満たす場合のみ）: マイナー/パッチ更新（PR タイトルの
  `from X to Y` から判定）・対象リポジトリに CI（`.github/workflows`）が存在する・
  コンフリクトが無い（`mergeable_state == "clean"`）
- 上記を満たさない PR（メジャーバージョンアップ・CI 未設定・バージョン判定不可・
  コンフリクトあり等）は自動マージせず Slack に通知するのみ。コンフリクトの場合は
  `@dependabot rebase` コメントを自動投稿する
- 自動マージした PR・要確認PRの両方を毎回 Slack に通知する（監査目的）
- **APScheduler / GitHub Actions のいずれにもスケジュール登録されていない。このエンドポイントを
  明示的に呼んだ時のみ実行される**（DEPSCAN 等の他クローラーと異なり自動実行なし）
- 実行結果は `GET /api/crawler-logs?crawler_type=DEPSOPS` で確認可能
  （`inserted`=自動マージ件数、`updated`=要確認件数）

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

**テスト結果（最新）:** 287 テスト / カバレッジ 98%

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

`app/` はドメイン（KEV / OSV / JVN / DEPSCAN / クローラーログ / 横断的共通処理）単位のパッケージ構成。各ドメインが `models.py`・`schemas.py`・`crawler.py`・`router.py` を1つのフォルダにまとめる。`tests/` も同じドメイン構成でミラーリングする。

```
cyberattack_info_api/
├── app/
│   ├── main.py                 # FastAPI アプリ本体・APScheduler 設定・ルーター include
│   ├── core/                   # 横断的インフラ（config・database・auth・db_utils・notifications・共通 schemas）
│   ├── kev/                    # CISA KEV ドメイン（models・schemas・crawler・router）
│   ├── osv/                    # OSV ドメイン（models・schemas・crawler・router）
│   ├── jvn/                    # JVN ドメイン（models・schemas・crawler・router）
│   ├── depscan/                # 依存ライブラリ脆弱性スキャン（DEPSCAN）ドメイン
│   │   └── parsers/            # 10 エコシステム分のロックファイルパーサー
│   ├── depsops/                # Dependabot PR 自動運用（DEPSOPS）ドメイン（models 無し。
│   │                           # crawler.py 相当は runner.py、router 無し・main.py で直接 include）
│   └── crawler_logs/           # クローラー実行ログドメイン（models・schemas・writer・router）
├── tests/                      # app/ と同じドメイン構成
│   ├── conftest.py             # テスト用フィクスチャ (SQLite テスト DB、全サブフォルダに自動継承)
│   ├── test_main.py            # app.main（health/root）テスト
│   ├── core/ kev/ osv/ jvn/ depscan/ depsops/ crawler_logs/
├── dashboard/               # Vercel デプロイの React ダッシュボード（KEV・OSV（Pub 含む 10 エコシステム）・JVN）
├── .github/
│   ├── dependabot.yml       # Dependabot（pip: / ・npm: /dashboard、週次で依存更新PRを自動作成）
│   └── workflows/
│       ├── ci.yml           # CI: lint + type check + test (PR 時に自動実行)
│       ├── deploy.yml       # CD: Render デプロイ (main マージ時に自動実行)
│       └── daily-crawl.yml  # 毎日クロール (単一 cron UTC 19:05 で KEV → OSV → JVN → DEPSCAN 順次実行)
├── .env.example         # 環境変数テンプレート
├── .python-version      # Python バージョン固定 (3.11)
├── requirements.txt     # 本番依存パッケージ
├── requirements-dev.txt # 開発・テスト依存パッケージ
├── pyproject.toml       # ruff / mypy / pytest 設定
├── security_report.html # セキュリティ脆弱性診断レポート
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
| `OSV_CRON_HOUR_UTC` | - | OSV クローラー実行時刻（時・UTC）（デフォルト: `20`） |
| `JVN_CRON_HOUR_UTC` | - | JVN クローラー実行時刻（時・UTC）（デフォルト: `21`） |
| `OSV_DAYS` | - | OSV 取得対象の直近日数（デフォルト: `30`） |
| `OSV_RETENTION_DAYS` | - | OSV データ保持期間（日数・デフォルト: `180`） |
| `JVN_DAYS` | - | JVN 取得対象の直近日数（デフォルト: `30`） |
| `GITHUB_TOKEN` | - | DEPSCAN/DEPSOPS 共用の GitHub PAT（fine-grained: Contents Read-only + **Issues Write** + **Pull requests Write** / classic: repo スコープ）。未設定時は DEPSCAN/DEPSOPS のみエラー終了。Issues Write が無い場合、Issue自動起票のみ失敗（DEPSCAN自体は成功扱い）。Pull requests Write が無い場合、DEPSOPSのPRマージ・rebase依頼のみ失敗 |
| `GITHUB_USERNAME` | ✅ | DEPSCAN のスキャン対象 GitHub アカウント。コード側にデフォルト値は持たないため、**未設定だとアプリ全体が起動しない** |
| `DEPSCAN_CRON_HOUR_UTC` | - | DEPSCAN 実行時刻（時・UTC）（デフォルト: `22`） |
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
| DEPSCAN で新規検知あり | `:rotating_light: 依存ライブラリ脆弱性を検知`（リポジトリ別グルーピング・パッケージ単位に集約したダイジェスト1通） |
| `POST /admin/dependabot-ops` 実行完了（自動マージ・要確認いずれかが1件以上） | `:robot_face: Dependabot PR 自動運用`（自動マージ済みPR一覧・要確認PR一覧と理由） |
| クローラーエラー発生時 | `:warning:` エラー内容（KEV / OSV / JVN / DEPSCAN / DEPSOPS それぞれ） |

### GitHub Issue 自動起票（DEPSCAN）

Slack 通知に加えて、DEPSCAN の新規検知は検知されたリポジトリ自身に GitHub Issue としても自動起票される。

- タイトル固定（`🚨 依存ライブラリの脆弱性が検出されました (DEPSCAN)`）。同名の Open な Issue が既にあればコメントを追記し、無ければ新規作成する（1リポジトリにつき常に1つの Open Issue に集約）
- 本文は Slack と同じくパッケージ単位に集約した形式
- `GITHUB_TOKEN` に `Issues: Write` 権限が無い場合、Issue 作成のみ失敗しログに警告が残る（DEPSCAN 自体は成功扱い）

---

## データ更新スケジュール

| タイミング | 処理 |
|----------|------|
| 毎日 JST 04:05（UTC 19:05）| GitHub Actions 単一 cron で KEV → OSV → JVN → DEPSCAN を順次実行 |
| アプリ起動時 | DB テーブルの自動作成 |
| `POST /admin/crawl` 実行時 | KEV 即時取得（スケジュール外） |
| `POST /admin/osv-crawl` 実行時 | OSV バックグラウンド取得（`?days=N` で日数指定可） |
| `POST /admin/jvn-crawl` 実行時 | JVN バックグラウンド取得（`?days=N` で日数指定可） |
| `POST /admin/depscan-crawl` 実行時 | DEPSCAN バックグラウンド取得（GitHub 全リポジトリを再スキャン） |
| `POST /admin/dependabot-ops` 実行時 | DEPSOPS バックグラウンド実行（**スケジュール登録なし・手動トリガーのみ**） |

> **Note:** APScheduler（アプリ内スケジューラ）も UTC 19:00 / 20:00 / 21:00 / 22:00 に設定されていますが、  
> Render Free プランのスリープ中は発火しません。GitHub Actions の単一 cron がその補完として機能します。
> DEPSOPS（Dependabot PR 自動運用）のみ、他クローラーと異なり APScheduler にも GitHub Actions にも
> スケジュール登録されていません。安全性確認のため、まずは明示的なAPI呼び出しでのみ動作する運用です。

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
