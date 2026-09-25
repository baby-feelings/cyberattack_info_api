# Cyberattack Info API

[![CI](https://github.com/baby-feelings/cyberattack_info_api/actions/workflows/ci.yml/badge.svg)](https://github.com/baby-feelings/cyberattack_info_api/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-98%25-brightgreen)](https://github.com/baby-feelings/cyberattack_info_api/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11-blue)](https://www.python.org/)

米 CISA の [Known Exploited Vulnerabilities (KEV) Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)・[OSV (Open Source Vulnerabilities)](https://osv.dev/)・[JVN (Japan Vulnerability Notes)](https://jvndb.jvn.jp/) を定期収集し、REST API として配信するプラットフォームです。  
Claude Code や CI/CD ツールから「今まさに悪用されているサイバー脅威」をリアルタイムに取得するために最適化されています。

---

## 機能

| 機能 | 説明 |
|------|------|
| **CISA KEV 自動クローラー** | 毎日 JST 04:05 に KEV → OSV → JVN → DEPSCAN → CODESCAN を順次実行（CISA KEV フィード取得・Upsert） |
| **OSV 自動クローラー** | 同上（OSV API から 10 エコシステムの主要パッケージの脆弱性を取得・Upsert） |
| **JVN 自動クローラー** | 同上（MyJVN API から国内脆弱性を取得・Upsert） |
| **依存ライブラリ脆弱性スキャン（DEPSCAN）** | 同上（GitHub 上の自作アプリ全リポジトリ〈プライベート含む〉のロックファイルを OSV API とリアルタイム照合。新規検知はリポジトリ自身に GitHub Issue も自動起票し、未解決 finding が0件になると自動クローズ。到達可能性〈import レベルのヒューリスティック〉も判定） |
| **DEPSCAN ダッシュボードの GitHub ログイン** | 任意の GitHub アカウントで OAuth ログインし、本人が所有するリポジトリの検知結果のみ閲覧可能（サーバー側で強制するアクセス制御）。ログイン時にオンデマンドでスキャンを実行し、直近 24 時間以内にスキャン済みなら再スキャンせず結果を即座に表示 |
| **自アプリコード脆弱性診断（CODESCAN）** | 同上（GitHub 上の自作アプリ全リポジトリのソースコードを tarball 取得し Semgrep〈p/security-audit + p/secrets〉で静的解析、さらに専用のシークレット検知ツール gitleaks も実行。SQLi・ハードコード認証情報・XSS・平文シークレット等を検知し、CVSS 3.1基本値をベストエフォートで推定。新規検知はリポジトリ自身に GitHub Issue も自動起票。ダッシュボードの閲覧には DEPSCAN と共有の GitHub ログインが必須〈オーナー絞り込みは無し〉） |
| **OSV 古いデータ自動削除** | 180 日以上前のレコードをクロール時に自動削除（DB 容量管理） |
| **削除済みリポジトリの自動データ削除** | 毎日クロールの後段で、GitHub上で実際に削除されたことを個別確認できたリポジトリのみ DEPSCAN/CODESCAN/DEPSOPS のデータを削除（アーカイブ化・一時的なAPI障害と誤判定しないよう安全側に倒す設計、Issue #228） |
| **ユーザー別 Slack 通知登録** | ダッシュボードのハンバーガーメニュー「設定」から、任意の GitHub アカウントで自分専用の Slack Webhook を登録可能（Issue #227）。登録は実際にテスト送信し成功した場合のみ保存。KEV/OSV/JVN の脅威情報は登録済みの全ユーザーへ、DEPSCAN/CODESCAN/DEPSOPS は本人自身の GitHub リポジトリの検知結果のみ本人へ通知。Webhook を登録した他ユーザー（`GITHUB_USERNAME` 以外）は自身のリポジトリに対する DEPSCAN/CODESCAN/DEPSOPS が定期的に実行され、本人のトークンで GitHub Issue 起票・Dependabot PR マージも行われる |
| **運用監視** | Prometheus + Grafana によるクローラー実行結果・ホストリソースの可視化（OCI上、任意） |
| **一覧取得 API** | ページネーション・キーワード検索・フィルタリング対応（KEV / OSV / JVN / DEPSCAN / CODESCAN） |
| **直近脅威 API** | 過去 N 日以内に追加された脆弱性を即座に取得（KEV） |
| **CVE 個別取得** | CVE ID を指定して脆弱性詳細を 1 件取得（KEV） |
| **統計 API** | ベンダー別ランキング・月別トレンド・重要度別集計（KEV / OSV / JVN / DEPSCAN / CODESCAN） |
| **クローラー実行ログ API** | KEV / OSV / JVN / DEPSCAN / CODESCAN クローラーの実行履歴（成否・件数・所要時間）を取得 |
| **Dependabot PR 自動運用（DEPSOPS）** | 安全性の高い Dependabot PR（マイナー/パッチ更新・CI あり・コンフリクトなし）のみ自動マージ。判定履歴（自動マージ・要確認いずれも、セキュリティ更新かのヒューリスティック判定・Compatibility score バッジ含む）は `GET /api/depsops` で後から確認可能 |
| **Slack 通知** | 新規追加・更新時に登録済みユーザーの Webhook へ自動通知（KEV / OSV / JVN / DEPSCAN / DEPSOPS / CODESCAN）。エラー通知のみ crawler_type に関わらず常に管理者（`GITHUB_USERNAME`）自身の Webhook にのみ送る |
| **手動クロール** | `POST /admin/crawl` / `POST /admin/osv-crawl` / `POST /admin/jvn-crawl` / `POST /admin/depscan-crawl` / `POST /admin/codescan-crawl` / `POST /admin/dependabot-ops` / `POST /admin/repo-cleanup` / `POST /admin/user-crawl`（バックグラウンド 202 即時返却・`?days=N` 対応） |
| **API キー認証** | `X-API-KEY` ヘッダーによるシンプルな固定キー認証 |
| **ヘルスチェック** | DB 接続確認付きの死活監視エンドポイント |
| **React ダッシュボード** | CISA KEV・OSV（Pub 含む 10 エコシステム・180 日表示）・JVN・DEPSCAN（GitHub ログイン必須、本人所有リポジトリのみ表示。到達可能性の判定結果も表示）・CODESCAN（GitHub ログイン必須〈DEPSCANとセッション共有、オーナー絞り込みは無し〉、CVSSベストエフォート推定値・検知ツール種別バッジを表示）を画面下部固定タブ（5つ）で切り替え表示。Dependabot 運用状況＝DEPSOPS の判定履歴は DEPSCAN タブ内のボタンから開く全画面モーダルとして統合（Vercel デプロイ） |

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

### 4. DBマイグレーションの適用

```bash
DATABASE_URL=sqlite:///./cyberattack_dev.db API_KEY=your-secret-key-here \
ENVIRONMENT=development GITHUB_USERNAME=your-github-username \
alembic upgrade head
```

新規に `alembic/versions/` へマイグレーションが追加された場合、`git pull` 後は毎回これを実行する。

### 5. 開発サーバーの起動

```bash
uvicorn app.main:app --reload --env-file .env.development
```

Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## API リファレンス

全エンドポイント（`/health` を除く）で `X-API-KEY` ヘッダーが必要です。curlの実行例・
パラメータ詳細・レスポンス例は **[.claude/skills/api-usage/SKILL.md](.claude/skills/api-usage/SKILL.md)**
に集約しているのでそちらを参照（本READMEでは重複を避け、エンドポイント一覧のみ示す）。ローカル開発時は
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
| GET | `/api/depscan/assets` | リポジトリ資産コンテキスト一覧（Issue #131） |
| GET | `/api/depscan/export` | DEPSCAN検知結果をCycloneDX/SPDX形式でエクスポート（`repo`必須、Issue #133） |
| GET | `/api/codescan` | CODESCAN検知結果一覧（Semgrep静的解析 + gitleaksシークレット検知。`cvss_score`はベストエフォート推定〈Issue #203〉。GitHubログイン必須〈`X-API-KEY`またはセッションJWT、Issue #219〉） |
| GET | `/api/codescan/stats` | CODESCAN統計（リポジトリ別・重要度別） |
| GET | `/api/depsops` | DEPSOPS判定履歴（`is_security_update`・`compatibility_badge_url`含む） |
| GET | `/api/crawler-logs` | クローラー実行ログ |
| GET | `/auth/github/login` | DEPSCANダッシュボードのGitHubログイン開始（ブラウザ専用） |
| POST | `/auth/exchange` | 交換コード→セッションJWT |
| GET | `/auth/scan-status` | オンデマンドスキャン進捗（Bearer認証） |
| GET/PUT/DELETE | `/auth/notification-settings` | ログイン中ユーザーのSlack Webhook通知登録・解除（Bearer認証、Issue #227）。PUTは実際にテスト送信し成功した場合のみ保存 |
| POST | `/admin/crawl` | KEV手動クロール |
| POST | `/admin/osv-crawl` | OSV手動クロール（`?days=N`対応） |
| POST | `/admin/jvn-crawl` | JVN手動クロール（`?days=N`対応） |
| POST | `/admin/depscan-crawl` | DEPSCAN手動実行 |
| PUT | `/admin/depscan/assets/{owner}/{repo}` | リポジトリ資産コンテキスト設定（Upsert、Issue #131） |
| POST | `/admin/codescan-crawl` | CODESCAN手動実行（GitHub全リポジトリをSemgrep + gitleaksで再スキャン） |
| POST | `/admin/dependabot-ops` | DEPSOPS手動実行（安全なPRのみ自動マージ） |
| POST | `/admin/repo-cleanup` | 削除済みリポジトリのDEPSCAN/CODESCAN/DEPSOPSデータ削除を手動実行（Issue #228） |
| POST | `/admin/user-crawl` | 登録済み他ユーザー（`GITHUB_USERNAME`以外、Webhook登録済み）向けDEPSCAN/CODESCAN/DEPSOPSを手動実行（Issue #227） |
| GET | `/taxii2/*` | TAXII 2.1配信（KEV/OSV/JVN 3コレクション購読用、最小実装。Issue #134） |
| GET | `/health` | ヘルスチェック（認証不要） |

クロール系の`/admin/*`（`*-crawl`・`dependabot-ops`）はバックグラウンド実行で即座に202を
返す（結果は`/api/crawler-logs`で確認）。`PUT /admin/depscan/assets/{owner}/{repo}`は
同期的なUpsertのため200を即時返す（バックグラウンド実行ではない）。
DEPSCANダッシュボードのGitHubログイン方式（使い捨て交換コード＋Bearerトークン、RFC 9700
対応・Safari ITP回避の経緯）や、Dependabot PRのマージ運用ルールは`CLAUDE.md`を参照。

---

## テストの実行

```bash
# 全テストを実行（カバレッジ付き）
pytest

# 特定のドメインのみ実行
pytest tests/kev/ -v
pytest tests/osv/ -v
pytest tests/jvn/ -v
pytest tests/depscan/ -v
pytest tests/codescan/ -v
pytest tests/auth/ -v

# HTML カバレッジレポートを生成して開く
pytest
start htmlcov/index.html  # Mac/Linux: open htmlcov/index.html
```

**テスト結果（最新）:** 805 テスト / カバレッジ 98%

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

`app/` はドメイン（KEV / OSV / JVN / DEPSCAN / CODESCAN / クローラーログ / 横断的共通処理）単位のパッケージ構成。各ドメインが `models.py`・`schemas.py`・`crawler.py`・`router.py` を1つのフォルダにまとめる。`tests/` も同じドメイン構成でミラーリングする。

```
cyberattack_info_api/
├── app/
│   ├── main.py                 # FastAPI アプリ本体・APScheduler 設定・ルーター include のみに専念
│   │                           # （/admin/* は持たない。各ドメインの router.py の admin_router に定義）
│   ├── auth/                   # GitHub ログイン・ユーザー別Slack通知登録ドメイン（models・account_store・
│   │                           # session・github_oauth・router。Issue #227でUserAccountテーブル追加）
│   ├── core/                   # 横断的インフラ（config・database・auth・background・crawler_runner・
│   │                           # crypto〈トークン暗号化〉・db_utils・notifications・pagination・
│   │                           # repo_cleanup〈削除済みリポジトリのデータ削除、Issue #228〉・
│   │                           # user_crawl_runner〈登録済み他ユーザー向け定期実行、Issue #227〉・共通 schemas）
│   ├── kev/                    # CISA KEV ドメイン（models・schemas・crawler・router〈router + admin_router〉）
│   ├── osv/                    # OSV ドメイン（models・schemas・crawler・router〈router + admin_router〉）
│   ├── jvn/                    # JVN ドメイン（models・schemas・crawler・router〈router + admin_router〉）
│   ├── depscan/                # 依存ライブラリ脆弱性スキャン（DEPSCAN）ドメイン
│   │   └── parsers/            # 10 エコシステム分のロックファイルパーサー
│   ├── depsops/                # Dependabot PR 自動運用（DEPSOPS）ドメイン（models・schemas・router
│   │                           # 〈router + admin_router〉。crawler.py 相当は runner.py）
│   ├── codescan/                # 自アプリコード脆弱性診断（CODESCAN）ドメイン（Semgrep静的解析 + gitleaks
│   │                           # シークレット検知。github_client・issue_management・cvss_mapping含む）
│   └── crawler_logs/           # クローラー実行ログドメイン（models・schemas・writer・router）
├── tests/                      # app/ と同じドメイン構成
│   ├── conftest.py             # テスト用フィクスチャ (SQLite テスト DB、全サブフォルダに自動継承)
│   ├── test_main.py            # app.main（health/root）テスト
│   ├── core/ kev/ osv/ jvn/ depscan/ depsops/ codescan/ crawler_logs/
├── dashboard/               # Vercel デプロイの React ダッシュボード（KEV・OSV（Pub 含む 10 エコシステム）・JVN・
│                           # DEPSCAN〈GitHub ログイン必須。Dependabot運用状況＝DEPSOPS の判定履歴も統合〉・
│                           # CODESCAN〈GitHub ログイン必須。DEPSCANとセッション共有。CVSSベストエフォート
│                           # 推定値・検知ツールバッジを表示〉を5つの固定タブで切り替え表示。ヘッダーの
│                           # ハンバーガーメニュー「設定」からSlack Webhook通知を登録可能、Issue #227）
├── alembic/                 # DBスキーマのマイグレーション管理（app.core.migrate から呼び出す）
│   └── versions/            # マイグレーションスクリプト（Gitで追跡）
├── .github/
│   ├── dependabot.yml       # Dependabot（pip: / ・npm: /dashboard、週次で依存更新PRを自動作成）
│   └── workflows/
│       ├── ci.yml                    # CI: lint + type check + test (PR 時に自動実行)
│       ├── deploy.yml                # CD: Vercel デプロイ (dashboard/変更時のmainマージ時のみ自動実行。バックエンドは手動デプロイ)
│       ├── daily-crawl.yml           # 毎日クロール (単一 cron UTC 19:05 で KEV → OSV → JVN → DEPSCAN → CODESCAN → DEPSOPS 順次実行)
│       ├── osv-scanner-scheduled.yml # OSV-Scanner: 本リポジトリ自身の依存関係を週次・mainマージ時にスキャン
│       ├── osv-scanner-pr.yml        # OSV-Scanner: PRで新規導入された脆弱性のみを差分検出
│       └── pip-audit.yml             # pip-audit: requirements.txtを週次・mainマージ時にスキャン
├── deploy/                  # OCIデプロイ関連（deploy_to_oci.ps1・docker-compose.yml・Caddyfile・
│   │                       # Grafanaプロビジョニング設定。秘密情報を含む.env/prometheus.ymlはgit管理外）
│   └── grafana/             # 運用監視ダッシュボードの自動プロビジョニング設定・ダッシュボードJSON
├── Dockerfile               # バックエンドのコンテナイメージ定義（OCI上でdocker composeがビルド）
├── .env.example         # 環境変数テンプレート
├── .python-version      # Python バージョン固定 (3.11)
├── requirements.txt     # 本番依存パッケージ
├── requirements-dev.txt # 開発・テスト依存パッケージ
├── pyproject.toml       # ruff / mypy / pytest 設定
├── security_report.html # セキュリティ脆弱性診断レポート
└── CLAUDE.md            # Claude Code 向け開発ガイド
```

---

## デプロイ（OCI + Neon）

バックエンド（FastAPI）はOracle Cloud Infrastructure（OCI）のCompute VM（Always Free、
Ampere A1）上でDocker Composeにより稼働する（旧Renderから移行済み）。デプロイは
`deploy/deploy_to_oci.ps1`を都度手動実行する運用で、GitHub Actions経由の自動デプロイは
無い（ダッシュボード＝Vercelのみ、`dashboard/`配下に変更がある`main`マージ時にのみ自動デプロイされる）。

### Step 1: Neon で PostgreSQL を作成

1. [Neon](https://neon.tech) でアカウント作成・プロジェクト作成
2. **Project name:** `cyberattack-info-api`、**Postgres version:** `16`、**Region:** `Singapore`
3. 接続文字列（`postgresql://...`）をコピー

### Step 2: OCI で Compute インスタンスを作成

1. [OCI コンソール](https://cloud.oracle.com/)で `Compute > Instances > Create Instance`
2. **Image:** Canonical Ubuntu（最新版）、**Shape:** `VM.Standard.A1.Flex`（Always Free対象。
   本APIは低負荷なため 1 OCPU / 6GB 程度で十分）
3. パブリックIPv4アドレスを割り当てる、SSHキーペアを生成してダウンロード
4. OCIセキュリティリスト・インスタンスOS側（`iptables` + `iptables-persistent`。Ubuntu標準
   イメージは `ufw` ではないため注意）の両方で80/443番ポートを開放する
5. SSH接続し、Docker Engine + Composeプラグインをインストール
   （`curl -fsSL https://get.docker.com | sh`）

### Step 3: デプロイ設定ファイルを準備

1. `deploy/.env.example` を `deploy/.env` にコピーし、`BACKEND_DOMAIN`（例:
   `<インスタンスのパブリックIP>.nip.io`。Let's EncryptのHTTPS自動化にドメイン名が必要な
   ため、IPアドレスをそのまま解決してくれる無料DNS `nip.io` を利用する）・
   `GRAFANA_DOMAIN`・`GRAFANA_ADMIN_PASSWORD` を設定する
2. `.env.example`（リポジトリルート）を元に `.env.production` を作成し、以下を設定
   （ローカル開発と同じファイルをそのままOCIへ転送して使う。本番専用の別ファイルは作らない）:

   | 変数名 | 値 |
   |--------|-----|
   | `DATABASE_URL` | Neon の接続文字列 |
   | `API_KEY` | 管理者用・フルアクセスの秘密キー（`openssl rand -hex 32`）。**ブラウザに配信されるダッシュボードには絶対に設定しないこと** |
   | `PUBLIC_API_KEY` | 公開ダッシュボード用の読み取り専用キー（任意・別途 `openssl rand -hex 32`）。Vercel の `VITE_PUBLIC_API_KEY` と同じ値を設定する |
   | `ENVIRONMENT` | `production` |
   | `GITHUB_USERNAME` | DEPSCAN/CODESCAN のスキャン対象アカウント（必須。未設定だとアプリが起動しない） |
   | `GITHUB_TOKEN` | DEPSCAN/DEPSOPS/CODESCAN 用 GitHub PAT（任意。未設定時は DEPSCAN/DEPSOPS/CODESCAN のみエラー終了） |
   | `GITHUB_OAUTH_CLIENT_ID` / `GITHUB_OAUTH_CLIENT_SECRET` | DEPSCAN ダッシュボードの GitHub ログイン用（任意。[GitHub Developer Settings](https://github.com/settings/developers) で OAuth App を作成して取得。Authorization callback URL は `https://<BACKEND_DOMAIN>/auth/github/callback`） |
   | `SESSION_SECRET_KEY` | セッションJWT署名鍵（任意。`python -c "import secrets; print(secrets.token_urlsafe(32))"` で生成） |
   | `API_BASE_URL_FOR_OAUTH` | 本API自身の公開URL（`https://<BACKEND_DOMAIN>`）。GitHub OAuth Appのcallback URLと一致させる |
   | `TOKEN_ENCRYPTION_KEY` | ユーザー別Slack通知登録（Issue #227）用、GitHubアクセストークン暗号化のFernet鍵（任意だが実質必須。`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` で生成。未設定だと登録済みユーザーの定期実行が機能しない） |
   | `METRICS_API_KEY` | Prometheus用メトリクスエンドポイント（`/metrics`）保護キー（任意。`openssl rand -hex 24`） |

3. `deploy/prometheus.yml.example` を `deploy/prometheus.yml` にコピーし、
   `credentials` に `METRICS_API_KEY` と同じ値を設定する（運用監視を使う場合）

### Step 4: デプロイ実行

`deploy/deploy_to_oci.ps1` 内の `$OciHost`（パブリックIP）・`$SshKey`（秘密鍵パス）を
実環境に合わせて書き換えた上で実行する:

```powershell
cd deploy
.\deploy_to_oci.ps1
```

SCPでコード一式を転送し、OCI上で `docker compose up -d --build` を実行する
（`api-prod`・`caddy`・`prometheus`・`grafana`・`node-exporter`）。

### GitHub Secrets の設定

| Secret 名 | 説明 |
|-----------|------|
| `API_KEY` | OCI の `.env.production` に設定した API キーと同じ値（`.github/workflows/daily-crawl.yml` 用） |
| `VERCEL_TOKEN` | [Vercelのアカウント設定](https://vercel.com/account/tokens)で発行したトークン（`.github/workflows/deploy.yml` 用。ダッシュボードの本番デプロイの唯一の経路のため必須） |
| `VERCEL_ORG_ID` / `VERCEL_PROJECT_ID` | Vercelプロジェクトの識別子（`dashboard/`で`vercel link`実行時に生成される`.vercel/project.json`から取得） |

ダッシュボード（Vercel）は `dashboard/` 配下に変更がある `main` ブランチへのマージで
自動デプロイされる（`.github/workflows/deploy.yml`。Vercel側のネイティブGit連携による
本番自動デプロイは無効化済みで、GitHub Actions経由のデプロイのみが本番に反映される）。

---

## 環境変数一覧

| 変数名 | 必須 | 説明 |
|--------|------|------|
| `DATABASE_URL` | ✅ | DB 接続文字列（SQLite or PostgreSQL） |
| `API_KEY` | ✅ | X-API-KEY 認証キー（管理者用・フルアクセス。十分に長いランダム文字列。**ダッシュボードには絶対に設定しないこと**） |
| `PUBLIC_API_KEY` | - | 公開ダッシュボード用の読み取り専用 X-API-KEY（任意。未設定時は読み取り専用エンドポイントも `API_KEY` のみで認証される） |
| `ENVIRONMENT` | - | `development` / `production`（デフォルト: `development`） |
| `CISA_KEV_URL` | - | CISA KEV フィード URL（通常は変更不要） |
| `CRON_HOUR_UTC` | - | KEV クローラー実行時刻（時・UTC）（デフォルト: `19`） |
| `CRON_MINUTE_UTC` | - | KEV クローラー実行時刻（分・UTC）（デフォルト: `0`） |
| `OSV_CRON_HOUR_UTC` | - | OSV クローラー実行時刻（時・UTC）（デフォルト: `20`） |
| `JVN_CRON_HOUR_UTC` | - | JVN クローラー実行時刻（時・UTC）（デフォルト: `21`） |
| `OSV_DAYS` | - | OSV 取得対象の直近日数（デフォルト: `30`） |
| `OSV_RETENTION_DAYS` | - | OSV データ保持期間（日数・デフォルト: `180`） |
| `JVN_DAYS` | - | JVN 取得対象の直近日数（デフォルト: `30`） |
| `GITHUB_TOKEN` | - | DEPSCAN/DEPSOPS/CODESCAN 共用の GitHub PAT（fine-grained: Contents Read-only + **Issues Write** + **Pull requests Write** / classic: repo スコープ）。未設定時は DEPSCAN/DEPSOPS/CODESCAN のみエラー終了。Issues Write が無い場合、Issue自動起票・自動クローズのみ失敗（DEPSCAN/CODESCAN自体は成功扱い）。Pull requests Write が無い場合、DEPSOPSのPRマージ・rebase依頼のみ失敗。DEPSOPS の `is_security_update` 判定には別途 Dependabot alerts の読み取り権限（fine-grained: 「Dependabot alerts: Read-only」/ classic: `security_events` スコープ）が必要（無い場合は判定結果が `null` のまま記録されるのみで、DEPSOPS本来のマージ判定には影響しない） |
| `GITHUB_USERNAME` | ✅ | DEPSCAN/CODESCAN のスキャン対象 GitHub アカウント。コード側にデフォルト値は持たないため、**未設定だとアプリ全体が起動しない** |
| `DEPSCAN_CRON_HOUR_UTC` | - | DEPSCAN 実行時刻（時・UTC）（デフォルト: `22`） |
| `DEPSCAN_RETENTION_DAYS` | - | DEPSCAN データの保持期間（日数・デフォルト: `180`）。解決済み（`resolved_at` 設定済み）のままこの日数を超えたレコードのみ自動削除（未解決レコードは対象外） |
| `CODESCAN_CRON_HOUR_UTC` / `CODESCAN_CRON_MINUTE_UTC` | - | CODESCAN 実行時刻（時・分・UTC）（デフォルト: `22`時`30`分。DEPSCANの後段） |
| `CODESCAN_RETENTION_DAYS` | - | CODESCAN データの保持期間（日数・デフォルト: `180`）。解決済みのままこの日数を超えたレコードのみ自動削除（未解決レコードは対象外） |
| `DEPSOPS_CRON_HOUR_UTC` | - | DEPSOPS 実行時刻（時・UTC）（デフォルト: `23`） |
| `REPO_CLEANUP_CRON_HOUR_UTC` / `REPO_CLEANUP_CRON_MINUTE_UTC` | - | 削除済みリポジトリのデータ削除実行時刻（時・分・UTC）（デフォルト: `23`時`15`分。DEPSOPSの後段、Issue #228） |
| `USER_CRAWL_CRON_HOUR_UTC` / `USER_CRAWL_CRON_MINUTE_UTC` | - | 登録済み他ユーザー向けDEPSCAN/CODESCAN/DEPSOPS実行時刻（時・分・UTC）（デフォルト: `23`時`30`分。削除済みリポジトリ掃除の後段、Issue #227） |
| `GITHUB_OAUTH_CLIENT_ID` | - | DEPSCAN ダッシュボードの GitHub ログイン用 OAuth App の Client ID。未設定時は `/auth/github/login` が `503` を返すのみ |
| `GITHUB_OAUTH_CLIENT_SECRET` | - | 同 OAuth App の Client Secret |
| `SESSION_SECRET_KEY` | - | セッショントークン（JWT・HS256）の署名鍵。未設定のまま本番運用しないこと |
| `TOKEN_ENCRYPTION_KEY` | - | ユーザー別Slack通知登録（Issue #227）用、GitHubアクセストークンをDBへ暗号化保存するFernet鍵。未設定時は登録済みユーザーの定期実行（DEPSCAN/CODESCAN/DEPSOPS）が機能しない |
| `FRONTEND_URL` | - | OAuth コールバック後にリダイレクトするダッシュボード URL（デフォルト: Vercel の本番URL） |
| `API_BASE_URL_FOR_OAUTH` | - | OAuth の `redirect_uri` 組み立てに使う本 API 自身の公開 URL。GitHub OAuth App の Authorization callback URL と一致させる必要がある（デフォルト・現在値: OCI インスタンスの URL） |
| `METRICS_API_KEY` | - | 運用監視（Prometheus）用の `/metrics` エンドポイント保護キー（`Authorization: Bearer` で認証）。未設定時は `/metrics` 自体が `503` を返すのみ |

---

## Slack 通知の設定（Issue #227：ユーザー別登録制）

固定の `SLACK_WEBHOOK_URL` 環境変数は廃止し、**各ユーザーがダッシュボードから自分の Slack Webhook を登録する方式**に変更した。

1. [Slack App Directory](https://your-workspace.slack.com/apps/A0F7XDUAZ-incoming-webhooks) で「Incoming WebHooks」を追加し、通知先チャンネルを選択して Webhook URL を取得
2. ダッシュボードのヘッダー右上のハンバーガーメニュー →「設定」から GitHub アカウントでログインし、取得した Webhook URL を貼り付けて「テスト送信して保存」を押す（実際にテスト通知を送信し、成功した場合のみ登録される）
3. `GITHUB_USERNAME`（`baby-feelings`）自身の毎日クロールの通知を引き続き受け取りたい場合も、`GITHUB_USERNAME` と同じ GitHub アカウントでログインしてこの画面から登録が必要（過去の `SLACK_WEBHOOK_URL` の値は自動移行されない）

### 通知先の解決ルール

| クローラー種別 | 送信先 |
|---------------|--------|
| KEV / OSV / JVN（リポジトリに紐づかないグローバルな脅威情報） | 通知を有効にしている**全登録ユーザー**へブロードキャスト |
| DEPSCAN / DEPSOPS / CODESCAN の毎日クロール（`GITHUB_USERNAME` 自身のリポジトリ対象） | `GITHUB_USERNAME` 自身が登録した Webhook にのみ送信 |
| DEPSCAN / DEPSOPS / CODESCAN の登録済み他ユーザー向け定期実行 | 本人が登録した Webhook にのみ送信 |
| **クローラーエラー発生時**（`:warning:`、KEV/OSV/JVN/DEPSCAN/DEPSOPS/CODESCAN 共通） | crawler_type に関わらず**常に管理者（`GITHUB_USERNAME`）自身の Webhook にのみ**送信（全登録ユーザーへはブロードキャストしない） |

通知内容:

| タイミング | 通知内容 |
|-----------|---------|
| CISA KEV クロール完了（新規追加・更新あり） | `:shield: CISA KEV 更新通知`（新規・更新件数） |
| OSV クロール完了（新規・更新あり） | `:package: OSV 脆弱性データ更新通知`（新規・更新・削除件数） |
| JVN クロール完了（新規・更新あり） | `:jigsaw: JVN 脆弱性データ更新通知`（新規・更新件数） |
| DEPSCAN（毎日クロール・登録済み他ユーザー向け実行）で新規検知あり | `:rotating_light: 依存ライブラリ脆弱性を検知`（リポジトリ別グルーピング・パッケージ単位に集約したダイジェスト1通） |
| CODESCAN（毎日クロール・登録済み他ユーザー向け実行）で新規追加・更新・削除あり | `:mag: 自アプリコード脆弱性更新通知`（新規・更新・削除件数。汎用フォーマット） |
| DEPSOPS実行完了（自動マージ・要確認いずれかが1件以上） | `:robot_face: Dependabot PR 自動運用`（自動マージ済みPR一覧・要確認PR一覧と理由） |

> **Note:** Webhook未登録のユーザーがダッシュボードにログインしただけでは、従来通り一切通知・GitHub Issue起票を行わない（Principle of Least Astonishment）。登録済み他ユーザー（`GITHUB_USERNAME`以外）向けのDEPSCAN/CODESCAN/DEPSOPSは、Webhook登録をopt-inのゲートとして使い、`USER_CRAWL_CRON_HOUR_UTC`で毎日定期実行される（本人のGitHubトークンでスキャン・Issue起票・Dependabot PRマージを行う）。

### GitHub Issue 自動起票（DEPSCAN / CODESCAN）

Slack 通知に加えて、DEPSCAN・CODESCAN の新規検知は検知されたリポジトリ自身に GitHub Issue としても自動起票される。

- タイトル固定。DEPSCAN: `🚨 依存ライブラリの脆弱性が検出されました (DEPSCAN)` / CODESCAN: `🔎 自アプリのコード脆弱性が検出されました (CODESCAN)`（両者は文字列で区別され混同しない）。同名の Open な Issue が既にあればコメントを追記し、無ければ新規作成する（1リポジトリにつき常に1つの Open Issue に集約）
- DEPSCANの本文は Slack と同じくパッケージ単位に集約した形式。CODESCANの本文はファイル・行・ルールID・CVSS単位（重要度降順）に整形
- `GITHUB_TOKEN` に `Issues: Write` 権限が無い場合、Issue 作成のみ失敗しログに警告が残る（DEPSCAN/CODESCAN 自体は成功扱い）

**Issue の自動クローズ（DEPSCANのみ）:** その後の再スキャンで、対象リポジトリの未解決 finding が実際に0件に
なったことを確認できると、Open な DEPSCAN Issue へ解決を報告するコメントを追加した上で自動的に
クローズする。トリガーは DEPSCAN の再スキャンでの検証後であり、Dependabot PR をマージした
直後には（本当に解消されたか未検証のため）クローズしない。CODESCANは現バージョンでは自動起票・追記のみで、
自動クローズは未実装（Issue側で手動運用）。

---

## データ更新スケジュール

| タイミング | 処理 |
|----------|------|
| 毎日 JST 04:05（UTC 19:05）| GitHub Actions 単一 cron で KEV → OSV → JVN → DEPSCAN → CODESCAN → DEPSOPS を順次実行 |
| アプリ起動時 | DB テーブルの自動作成 |
| `POST /admin/crawl` 実行時 | KEV 即時取得（スケジュール外） |
| `POST /admin/osv-crawl` 実行時 | OSV バックグラウンド取得（`?days=N` で日数指定可） |
| `POST /admin/jvn-crawl` 実行時 | JVN バックグラウンド取得（`?days=N` で日数指定可） |
| `POST /admin/depscan-crawl` 実行時 | DEPSCAN バックグラウンド取得（GitHub 全リポジトリを再スキャン） |
| `POST /admin/codescan-crawl` 実行時 | CODESCAN バックグラウンド取得（GitHub 全リポジトリを Semgrep + gitleaks で再スキャン） |
| `POST /admin/dependabot-ops` 実行時 | DEPSOPS バックグラウンド実行（Dependabot PR の自動マージ判定） |
| `POST /admin/repo-cleanup` 実行時 | 削除済みリポジトリのDEPSCAN/CODESCAN/DEPSOPSデータ削除（Issue #228） |
| `POST /admin/user-crawl` 実行時 | 登録済み他ユーザー向けDEPSCAN/CODESCAN/DEPSOPS（Webhook登録済みユーザーのみ、Issue #227） |

> **Note:** APScheduler（アプリ内スケジューラ）は UTC 19:00 / 20:00 / 21:00 / 22:00 / 22:30 / 23:00 /
> 23:15 / 23:30（KEV/OSV/JVN/DEPSCAN/CODESCAN/DEPSOPS/削除済みリポジトリ掃除/登録済み他ユーザー向け
> の順）に設定されており、OCI移行後はこちらが主経路として機能する（OCIは常時稼働のためスリープしない）。
> GitHub Actions の単一 cron（KEV〜DEPSOPSのみ）は、ネットワーク障害等で APScheduler が不発火だった
> 場合の二重バックアップとして維持している（削除済みリポジトリ掃除・登録済み他ユーザー向け実行は
> APScheduler側のみ）。

---

## Claude Code での活用例

Claude Code や他のAIエージェントからの利用パターン・実行例は
**[.claude/skills/api-usage/SKILL.md](.claude/skills/api-usage/SKILL.md)** を参照。

---

## ライセンス

[GNU Affero General Public License v3.0（AGPL-3.0）](LICENSE)

AGPL-3.0 は、コードを改変してネットワーク経由で提供する場合（本 API のようなサーバー型サービスとしての利用を含む）も、改変後のソースコードを利用者に公開する義務を課す強めのコピーレフトライセンスです。無断でコードをコピーして非公開の競合サービスとして運営することを防ぐ目的で選択しています。個人利用・学習目的の閲覧・フォークは自由ですが、本コードを基にしたサービスを公開する場合はソースコードの公開が必要です。商用利用や別ライセンスでの利用を希望する場合は個別にご相談ください。
