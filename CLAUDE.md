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
# DBマイグレーション適用（初回セットアップ・pull後に新しいマイグレーションがある場合）
alembic upgrade head

# 新しいモデル変更からマイグレーションを生成
alembic revision --autogenerate -m "説明"

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

`app/` はドメイン（KEV / OSV / JVN / DEPSCAN / クローラーログ / 横断的共通処理）単位のパッケージで構成する。各ドメインは `models.py`（ORM）・`schemas.py`（Pydantic）・`crawler.py`（クローラー）・`router.py`（API）を1つのフォルダにまとめ、高凝集を保つ。`app/main.py` はエントリポイント固定（`uvicorn app.main:app`）のため直下から動かさない。

```
app/
├── main.py                 # FastAPI アプリ・lifespan・スケジューラ登録・ルーター include
│                           # /admin/crawl・/admin/osv-crawl・/admin/jvn-crawl・/admin/depscan-crawl
│                           # /admin/dependabot-ops
├── auth/                   # GitHub ログイン（DEPSCAN ダッシュボードのアクセス制御）ドメイン。models 無し
│   ├── router.py           # /auth/github/login・/auth/github/callback・/auth/scan-status
│   ├── github_oauth.py     # GitHub OAuth（Web Application Flow）クライアント
│   └── session.py          # セッショントークン（JWT）の発行・検証
├── core/                   # 横断的インフラ（特定ドメインに属さない）
│   ├── config.py           # Settings（pydantic-settings）・環境変数管理
│   ├── database.py         # SQLAlchemy エンジン（SQLite/PG 切り替え）・get_db
│   ├── auth.py             # X-API-KEY 認証（APIKeyHeader・hmac.compare_digest）
│   ├── db_utils.py         # DB ユーティリティ（year_month_expr: SQLite/PG 両対応の日付フォーマット）
│   ├── notifications.py    # Slack Webhook 通知（notify_success/notify_error 共通化・エラーサニタイズ）
│   ├── osv_client.py       # OSV API 汎用クライアント（query_versions_batch・fetch_vuln_by_id・
│   │                       # parse_severity 等。app.osv.crawler と app.depscan.crawler の両方が利用）
│   ├── types.py            # CrawlerType（"KEV"/"OSV"/"JVN"/"DEPSCAN"/"DEPSOPS" の Literal 型）
│   └── schemas.py          # 横断スキーマ（HealthResponse・MonthlyStat・SeverityStat）
├── kev/                    # CISA KEV ドメイン
│   ├── models.py           # Vulnerability
│   ├── schemas.py          # VulnerabilityOut 等
│   ├── crawler.py          # CISA KEV クローラー・Upsert ロジック
│   └── router.py           # /api/vulnerabilities エンドポイント（一覧・個別・統計）
├── osv/                    # OSV ドメイン
│   ├── models.py           # OsvVulnerability
│   ├── schemas.py          # OsvVulnerabilityOut 等
│   ├── crawler.py          # OSV クローラー（REST API 方式・10 エコシステム対応、Upsert ロジック）
│   ├── packages.py         # POPULAR_PACKAGES（監視対象パッケージ一覧、ロジックから分離したデータ）
│   └── router.py           # /api/osv エンドポイント（一覧・統計）
├── jvn/                    # JVN ドメイン
│   ├── models.py           # JvnVulnerability
│   ├── schemas.py          # JvnVulnerabilityOut 等
│   ├── crawler.py          # JVN クローラー（MyJVN API / RDF-RSS）
│   └── router.py           # /api/jvn エンドポイント（一覧・統計）
├── depscan/                # 依存ライブラリ脆弱性スキャン（DEPSCAN）ドメイン
│   ├── models.py           # DependencyFinding・UserScan（GitHub ログイン経由のオンデマンドスキャン状況）
│   ├── schemas.py          # DependencyFindingOut 等
│   ├── crawler.py          # GitHub 全リポジトリのロックファイルを OSV API とリアルタイム照合。
│   │                       # run_depscan_for_user/get_user_scan_status/should_rescan_for_user
│   │                       # （GitHub ログイン経由のオンデマンドスキャン）も含む
│   ├── router.py           # /api/depscan エンドポイント（一覧・統計。X-API-KEY またはセッション
│   │                       # トークンの二重認証）
│   ├── github_client.py    # GitHub API クライアント（リポジトリ一覧・ツリー・ファイル取得）
│   └── parsers/            # 10 エコシステム分のロックファイルパーサー
├── depsops/                # Dependabot PR 自動運用（DEPSOPS）ドメイン。models/router 無し
│   ├── runner.py           # crawler.py 相当。run_dependabot_ops（判定・マージ・Slack通知）
│   ├── github_client.py    # GitHub API クライアント（PR一覧・詳細・マージ・rebase依頼・CI有無判定）
│   └── classify.py         # PRタイトルからのバージョンアップ種別判定（classify_bump）
└── crawler_logs/           # クローラー実行ログドメイン
    ├── models.py           # CrawlerLog
    ├── schemas.py          # CrawlerLogOut
    ├── writer.py           # write_crawler_log・now_utc（KEV/OSV/JVN/DEPSCAN/DEPSOPS 各クローラーから利用）
    └── router.py           # /api/crawler-logs エンドポイント（実行ログ一覧）

tests/                      # app/ と同じドメイン構成でミラーリング
├── conftest.py             # テスト DB・client・db_session フィクスチャ（全サブフォルダに自動継承）
├── test_main.py            # app.main（health/root）テスト
├── auth/                   # GitHub OAuth クライアント・セッショントークン・ログインAPIテスト
├── core/                   # DB エンジン・Slack 通知テスト
├── kev/                    # KEV クローラー・API テスト
├── osv/                    # OSV クローラー・API テスト
├── jvn/                    # JVN クローラー・API テスト
├── depscan/                # DEPSCAN クローラー・API・パーサーテスト
├── depsops/                # DEPSOPS 判定ロジック・GitHub操作・Slack通知テスト
└── crawler_logs/           # クローラーログ API テスト

dashboard/               # Vercel デプロイの React ダッシュボード
                         # CISA KEV・OSV（Pub 含む 10 エコシステム・180 日表示）・JVN・
                         # DEPSCAN（GitHub ログイン必須。本人所有リポジトリのみ表示）を
                         # 画面下部固定タブで切り替え表示

alembic/                 # DBスキーマのマイグレーション管理
├── env.py               # Base.metadata・全モデル import・DATABASE_URL 設定
└── versions/            # マイグレーションスクリプト（Git管理下。app.core.migrate から適用）

.github/
├── dependabot.yml   # Dependabot（pip: / ・npm: /dashboard、週次で依存更新PRを自動作成）
└── workflows/
    ├── ci.yml           # CI: ruff → mypy → pytest（PR 時・Python 3.10/3.11 matrix）
    ├── deploy.yml       # CD: Render Deploy Hook トリガー（main マージ時）
    └── daily-crawl.yml  # 毎日クロール: 単一 cron(UTC 19:05) で KEV → OSV → JVN → DEPSCAN → DEPSOPS を順次実行
```

---

## 重要な実装上の注意事項

### 公開ダッシュボード用キー（PUBLIC_API_KEY）と管理者用キー（API_KEY）の分離
React ダッシュボード（`dashboard/`）は Vercel でビルドされ静的資産としてブラウザに配信される。
Vite の `VITE_` 接頭辞の環境変数はビルド時に JS バンドルへ平文で埋め込まれるため、
ダッシュボードに管理者用 `API_KEY`（`/admin/crawl`・`/admin/dependabot-ops` 等、書き込み・
実行系エンドポイントも保護する単一キー）を設定すると、誰でもバンドルから抽出して
管理操作を実行できてしまう（実際に本番でこの状態が発生し、キーローテーションで対応した
インシデントあり）。これを防ぐため、読み取り専用エンドポイント（KEV/OSV/JVN/crawler-logs
の各 router）だけは `app.core.auth.require_public_api_key`（`API_KEY` または
`PUBLIC_API_KEY` のいずれかを許可）で保護し、ダッシュボードの `VITE_PUBLIC_API_KEY` には
`PUBLIC_API_KEY` の値のみを設定する。`/admin/*`（`app/main.py`）は従来通り
`require_api_key`（`API_KEY` のみ許可）のままで、`PUBLIC_API_KEY` では通らない。
DEPSCAN（`app/depscan/router.py`）はダッシュボードから `X-API-KEY` を一切送らず GitHub
ログインのセッショントークンのみを使うため、この分離の対象外（`_resolve_access` は
引き続き `API_KEY` のみを直接比較する）。Claude Code 等の既存クライアントは引き続き
`API_KEY` を使えばよく、SKILL.md の運用は変わらない。

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
2 つの汎用関数に統合。各クローラー（KEV/OSV/JVN/DEPSCAN/DEPSOPS）はこれらを直接呼び出す
（`notify_new_vulnerabilities` 等のクローラー別ラッパーは廃止済み、DRY違反だったため削除）。
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

### DBマイグレーションは Alembic で管理する（`Base.metadata.create_all` 単独運用からの移行）
EPSS スコア用カラム追加（Issue #127）を機に、これまで未初期化のまま `requirements.txt` に
入っているだけだった Alembic を正式導入した。`app/main.py` の lifespan が呼ぶ
`Base.metadata.create_all()` は新規テーブルの作成のみ行い、既存テーブルへの列追加はしない
ため、本番 Neon DB のような**既に稼働中のDBへのスキーマ変更**は create_all だけでは反映
されない。今後カラム追加・変更を伴う機能は、モデル変更後に
`alembic revision --autogenerate -m "..."` でマイグレーションを生成し、`alembic/versions/`
配下にコミットすること（`.gitignore` から除外済み・Git管理下）。

`app/core/migrate.py` の `run_migrations()`（`python -m app.core.migrate` で実行）が
実際のマイグレーション適用を担う。**FastAPI の lifespan には組み込まない**
（`tests/conftest.py` が `Base.metadata.create_all` で直接テーブルを作る既存のテストDBに
対し、意図せず alembic の管理外操作が走ってテストが壊れるのを避けるため）。Render の
Start Command で `python -m app.core.migrate && uvicorn ...` として、アプリ起動前に
明示的に呼び出す運用とする。

**既存DB（alembic導入前）への一度きりの移行を自動化する自己修復ロジック**: `vulnerabilities`
テーブルは存在するが `alembic_version` テーブルが無い場合（＝create_allだけで運用してきた
既存DB）、現在のスキーマに一致するベースラインリビジョン（`_BASELINE_REVISION`、
EPSS カラム追加前の状態）へ自動的に `stamp`（DDLを実行せず「そこまで適用済み」と記録する
だけ）してから `upgrade head` する。これにより、本番DBのシェルに直接入って手動で
`alembic stamp` する必要がなく、Render の Start Command 変更だけで安全に移行できる。
真に空の新規DB（`vulnerabilities` テーブル自体が無い）の場合は stamp をスキップし、
先頭のリビジョンから全て適用する。

### KEV クローラーの EPSS スコア連携（Issue #127）
FIRST が提供する EPSS（Exploit Prediction Scoring System）API（認証不要、
`https://api.first.org/data/v1/epss`）から、KEV に登録済みの全 CVE の悪用確率
スコア・パーセンタイルを取得し `Vulnerability.epss_score`/`epss_percentile`/
`epss_updated_at` に格納する。1リクエストあたり `_EPSS_BATCH_SIZE`（100件）ずつ
`cve=CVE-1,CVE-2,...` とカンマ区切りで問い合わせる（KEVは1600件超あるため）。
EPSS スコアはCVEの内容が変わらなくても日次で変動するモデル値のため、
**毎回のKEVクロールで全件を再取得・上書き**する（差分検知はしない）。
EPSS API 呼び出し失敗は他の保持期間削除処理と同様 try/except で握りつぶし、
KEVクロール自体の成功可否には影響させない。`GET /api/vulnerabilities` に
`min_epss` クエリパラメータを追加し、KEV単独では拾えない悪用確率シグナルでの
絞り込みを可能にした。

### OSV クローラーの 2 ステップ取得
OSV REST API の `/v1/querybatch` は `{id, modified}` しか返さないため、完全情報の取得は 2 ステップ:
1. `POST /v1/querybatch` → 脆弱性 ID と最終更新日時の一覧を取得
2. cutoff（`OSV_DAYS` 日前）より新しいものだけ `GET /v1/vulns/{id}` で完全情報を取得

### OSV クローラーの対象エコシステム
`app/osv/packages.py` の `POPULAR_PACKAGES` dict に定義された 10 エコシステムの主要パッケージを監視対象とする:
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

### DEPSCAN はリアルタイムで OSV API に照合する（事前クロール済みデータには頼らない）
既存の `OsvVulnerability` テーブルは `POPULAR_PACKAGES`（各エコシステム50〜60件の主要パッケージ）しか
収録していないため、GitHub 上の自作アプリが依存する任意のパッケージを検知するには不十分。
そのため DEPSCAN は `app.core.osv_client.query_versions_batch` で **バージョン指定の OSV API を
その場でクエリ**し、既存 DB とは独立して脆弱性を判定する。GitHub リポジトリの列挙は
`GITHUB_USERNAME`（fork・archived は自動除外）、認証は `GITHUB_TOKEN`（fine-grained PAT,
Contents: Read-only + **Issues: Write** 推奨）を使用する。

### `list_target_repos` はプライベートリポジトリも対象に含める
`GET /users/{username}/repos`（公開リポジトリのみ返す仕様）ではなく、認証ユーザー自身の
視点で全リポジトリを返す `GET /user/repos`（`affiliation=owner`）を使う。前者を使っていた際は
プライベートリポジトリが一切スキャンされないバグがあった（PR #72 で修正）。

### DEPSCAN の新規検知は GitHub Issue としても自動起票する
`app.depscan.crawler._file_github_issues` が、新規検知を検知されたリポジトリ自身に
Issue として起票する（Slack通知と同じ `new_snapshots` を使用）。タイトル固定文字列で
Open Issue を検索し、あれば `add_issue_comment` で追記、無ければ `create_issue` で新規作成する
（1リポジトリにつき常に1つの Open Issue に集約するため）。本文の整形ロジック
（`format_package_lines`）は Slack 通知（`app.core.notifications`）と共有するため
`app.core.finding_format` に切り出してある。GitHub API 呼び出し失敗（`Issues: Write` 権限
不足等）はリポジトリ単位で `except httpx.HTTPError` により握りつぶし、DEPSCAN 全体の
成功可否には影響させない。

### DEPSCAN の解決済みレコードは保持期間超過で自動削除する（未解決は対象外）
`app.depscan.crawler._delete_old_depscan_records` が、`resolved_at` が
`DEPSCAN_RETENTION_DAYS`（デフォルト 180 日）より古いレコードのみを削除する
（KEV/OSV/JVN と同様の DB 容量管理）。**未解決のレコードは経過期間に関わらず削除しない**
（対応が必要な情報のため、履歴として残す）。`_resolve_stale_findings` の直後・
`fetch_and_scan_dependencies` 内で呼ばれ、削除失敗はクロール全体を失敗させないよう
try/except で握りつぶす（KEV/OSV/JVN の削除処理と同じ方針）。

`CrawlerLog`（`crawler_type="DEPSCAN"`）の `inserted`/`updated`/`deleted` は他クローラーと
意味が異なる点に注意: `inserted`=新規検知件数（共通）、`deleted`=今回のスキャンで解決済みに
した件数（削除ではない。既存の挙動を維持するため据え置き）、`updated`=今回新設した保持期間
超過の**実削除**件数（DEPSCAN の `updated` は元々常に 0 だったため、新しいカラムを追加せずに
ここへ格納している）。

### Dependabot を本リポジトリおよび DEPSCAN 対象の全リポジトリで有効化している
DEPSCAN が「検知」、Dependabot が「実際の修正 PR 作成」を担う役割分担。本リポジトリの
`.github/dependabot.yml` は `pip`（`/`）・`npm`（`/dashboard`）を週次でチェックする。

GitHub の Dependabot には独立した2つの機能があり、**`dependabot.yml` を置くだけでは
「Dependabot version updates」（週次の通常バージョンアップPR）しか有効にならない**。
DEPSCAN が検知したような脆弱性に対して即座に修正PRを出す「Dependabot security updates」は、
各リポジトリの `Settings → Code security` で個別に ON にする必要がある（`Dependency graph`・
`Dependabot alerts`・`Dependabot security updates` の3点、`Grouped security updates` も
推奨）。有効化すると、既存の Open な Dependabot alert 全件に対して自動でPRが作成される。
**Dependabot PR は内容を確認せず自動マージしないこと。** マイナー/パッチ更新は概ね安全だが、
メジャーバージョンアップは非互換な依存衝突を起こしうる（実例: `typescript` 6.0.3→7.0.2 が
`typescript-eslint@8.61.0` の peer 依存 `typescript >=4.8.4 <6.1.0` と衝突し、Vercel の
`npm install` が失敗した。`typescript-eslint` 側が TypeScript 7 系に対応するまで `~6.0.3` に
固定している）。マージ前に CI（Test & Lint）に加え、フロントエンド変更は Vercel のプレビュー
デプロイが `Deployment has completed` になっているかを確認する。マージ後にビルドが壊れた場合は
該当パッケージのバージョンを差し戻す fix PR で対応する。

DEPSCAN 対象の他リポジトリ（`baby-feelings` アカウント配下）でも同様に Dependabot を有効化
済み。それらの PR をマージする際のチェックリスト:

1. マージ前に `mergeable: MERGEABLE` を確認する（`gh pr view <num> --json mergeable`）。CI が
   設定されていないリポジトリも多く、その場合は内容確認のみで判断する
2. メジャーバージョンアップは上記と同様、マージ後のデプロイ結果を確認してから次に進む
3. 複数の Dependabot PR を連続でマージすると、後続 PR が `package-lock.json` 等の競合で
   `Pull Request has merge conflicts` になることがある。その場合は該当 PR に
   `@dependabot rebase` とコメントすればリベースされる（数分待って再マージ）
4. リベース後、対象パッケージが別 PR のマージで既に修正済みバージョンに達していた場合、
   Dependabot が PR を自動でクローズすることがある（`state: CLOSED`, `mergedAt: null`）。
   これは異常ではなく「対応不要になった」ことを意味する
5. **本番反映方法はリポジトリごとに異なる**。Vercel 連携があるリポジトリはマージ時点で
   自動デプロイされるが、`todo-app`（Firebase Hosting）のように CI/CD が無いリポジトリは
   マージ後にローカルで `git pull` した上で手動デプロイコマンド（例: `firebase deploy`）を
   実行するまで本番に反映されない

### 新規リポジトリ作成時のチェックリスト（Dependabot）
`baby-feelings` は Organization ではなく個人アカウントのため、Organization 全体への
一括デフォルト設定が存在しない。**新しいリポジトリを作るたびに、以下を個別に対応する
必要がある**（DEPSCAN 自体は `list_target_repos` が毎回全リポジトリを再取得するため
追加対応不要だが、Dependabot 側は明示的な設定が要る）。

1. `.github/dependabot.yml` を追加する（version updates。ロックファイルのエコシステムに
   合わせて `package-ecosystem` を指定する。対応エコシステムは
   `app.depscan.parsers.LOCKFILE_FILENAMES` を参照）
2. `Dependabot alerts` と `Dependabot security updates` を有効化する（security updates。
   UI からは各リポジトリの `Settings → Code security` だが、GitHub API からも一括操作可能）:
   ```bash
   gh api -X PUT repos/baby-feelings/<repo>/vulnerability-alerts
   gh api -X PUT repos/baby-feelings/<repo>/automated-security-fixes
   ```
2つとも忘れた場合でも、DEPSCAN 自体は毎日そのリポジトリを検知対象に含め Slack/Issue で
通知するため「気づけない」ことはないが、Dependabot による自動修正PRの生成が遅れる
（1を忘れると Dependabot が全く反応しない、2を忘れると週次の遅い version updates 頼みになる）。

### DEPSOPS（`app/depsops/`）: Dependabot PR の安全な自動マージ運用層
DEPSCAN（検知）・Dependabot（修正PR作成）に続く3層目として、Dependabot PR のうち
**安全性が高いものだけを自動マージする**運用層。`POST /admin/dependabot-ops` から
`app.depsops.runner.run_dependabot_ops` を呼ぶ。当初は安全性確認のため
APScheduler/GitHub Actions への登録なし・手動トリガーのみで運用していたが、
半日ほど手動運用して問題ないことを確認した上で、他クローラーと同様に
`DEPSOPS_CRON_HOUR_UTC`（デフォルト UTC 23:00 = JST 8:00、DEPSCAN の後段）で
自動実行するようにした（`app/main.py` の `scheduler.add_job` および
`.github/workflows/daily-crawl.yml` の `dependabot-ops` ジョブ）。
コンフリクトで自動マージできなかった PR（rebase 依頼のみで終わった PR）は、
翌日以降の実行時にリベースが完了していれば通常通り自動マージされる
（複数日にまたがる自己修復。追加のポーリング処理等は無く、単に毎日の
再実行が同じ判定ロジックを通るだけ）。

判定ロジック（`_process_pr`）:
1. `mergeable_state == "dirty"`（コンフリクト）→ `@dependabot rebase` をコメントして
   flagged 扱い（マージしない）
2. 対象リポジトリに CI（`.github/workflows` の存在）が無い → 常に flagged
   （CI が無いと自動マージの安全性を検証する手段が無いため）
3. PR タイトルから `app.depsops.classify.classify_bump` で判定した結果が
   `"major"` または `"unknown"`（タイトルから `from X to Y` 形式のバージョンを
   抽出できない grouped PR 等）→ flagged
4. `mergeable_state != "clean"`（CI 失敗・レビュー待ち等）→ flagged
5. 上記いずれにも該当しない（マイナー/パッチ・CI あり・コンフリクトなし）→ 自動マージ

`classify_bump` は正規表現でタイトルから `from X to Y` を抽出し、メジャーバージョン
（`major.minor` の `major`）が変わっていれば `"major"` とする。**0.x 系は minor の
変化も `"major"` 扱いにする**（semver の慣習で 0.x は minor が実質的な破壊的変更を
意味するため）。バージョンが抽出できない場合は安全側に倒し `"unknown"` とし、
自動マージしない。

マージ・要確認（flagged）いずれも `notify_dependabot_ops`（`app.core.notifications`）で
**毎回** Slack 通知する（0 件同士の場合のみスキップ）。監査性を優先し、自動マージした
という事実も必ず可視化する設計。crawler_logs には `crawler_type="DEPSOPS"` で記録し、
`inserted`=自動マージ件数、`updated`=要確認件数として保存する（`deleted` は未使用）。

`app.depsops.github_client` は `app.depscan.github_client` とは別モジュール
（ロックファイル収集とPR運用でドメインが異なるため）。ただし `list_target_repos`
（対象リポジトリ一覧取得）は DEPSCAN 側のものをそのまま import して再利用している
（DRY。リポジトリ一覧取得ロジック自体はドメイン非依存のため）。

### DEPSCAN のロックファイル検出は Git Tree API で1リポジトリ1回のみ
`app.depscan.github_client.get_repo_tree` で `git/trees/{branch}?recursive=1` を使い、
サブディレクトリ（monorepo）も含めて全ファイルパスを1回のAPI呼び出しで取得する。
対応する10エコシステムのロックファイル名は `app.depscan.parsers.LOCKFILE_FILENAMES` で判定する。

### GITHUB_USERNAME は必須環境変数（デフォルト値なし）
`GITHUB_TOKEN`（DEPSCAN 専用、未設定でもアプリは起動しDEPSCANだけがエラー終了）とは異なり、
`GITHUB_USERNAME` は `app/core/config.py` の `Settings` でデフォルト値を持たない必須項目。
未設定だと `Settings()` のインスタンス化（アプリ起動時）に失敗し、**アプリ全体が起動できない**。
ローカル開発・CI 双方で `GITHUB_USERNAME` を環境変数として明示的に設定する必要がある
（`tests/conftest.py` の `os.environ.setdefault` と `.github/workflows/ci.yml` の `env:` を参照）。

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

### ダッシュボードのタブ切り替え UI（App.tsx）
KEV / OSV / JVN の 3 データソースは、画面下部固定のタブバーで切り替え表示する構成（縦並び表示ではない）。
`TabKey` / `TABS` 定数と `activeTab` state で選択中セクションのみを条件レンダリングし、
サーバー稼働状況（`HealthStatus`）とエラーバナーは全タブ共通で常に表示する。
タブには `role="tablist"/"tab"/"tabpanel"` と `aria-selected`/`aria-controls`/`aria-labelledby` を付与済み。

### OsvPanel/JvnPanel の共通パーツ（VulnPanelParts.tsx）
`dashboard/src/components/shared/VulnPanelParts.tsx` に、両パネルで共通の
`SeverityBadge`・`ChartCard`・`SeverityPieChart`・`MonthlyBarChart`・`TableLoadingSkeleton`・
`EmptyState`・`Pagination`・`SeverityFilterButtons`・`SearchBox`・`SortSelector` を切り出し済み。
深刻度の値・配色（OSV: CRITICAL/HIGH/MEDIUM/LOW、JVN: High/Medium/Low）はドメイン固有のため
`classMap`/`colorMap` として呼び出し側から渡す。エコシステム別棒グラフ（OSV固有）や行コンポーネント
（OsvRow/JvnRow）はドメイン固有のため各パネル側に残している。
`ChartCard` の `footer` スロットは高さ固定領域の**外側**に描画されるため、円グラフの凡例のように
高さ制約に含めたくないコンテンツはここに渡すこと。

### DepscanPanel のオーナーフィルターは repo_full_name から導出（バックエンドは owner クエリのみ追加）
`GET /api/depscan` にリポジトリオーナー絞り込み用の `owner` クエリパラメータを追加した
（`repo_full_name LIKE '{owner}/%'`。既存の `repo`（完全一致）とは別軸）。オーナーの選択肢
自体は `DepscanPanel.tsx` 側で `stats.repos`（`/api/depscan/stats` が返す未解決リポジトリ一覧）
から `repo_full_name.split('/')[0]` を抽出して動的に生成しており、専用の一覧APIは無い。
これは DEPSCAN が実際にスキャンした（＝DB に保存済みの）リポジトリのみを反映するため、
`GITHUB_TOKEN` の権限外のリポジトリ情報が混入することはない。オーナーが1種類のみの場合は
フィルターボタン自体を非表示にする（現状 `baby-feelings` のみのため）。

### DepscanPanel はパッケージ×バージョン単位に集約して表示する（クライアント側集約）
`GET /api/depscan` は「パッケージ×CVE」単位で1件返す仕様（`DependencyFinding` の
ユニークキーが `(repo_full_name, ecosystem, package_name, osv_id)` のため）。1パッケージに
複数の CVE が紐づく場合（例: 1リポジトリの `cryptography` に13件のGHSAがヒット）、
そのままテーブル表示すると「実際のパッケージ数よりずっと多い件数」に見えてしまい、
Dependabot の PR 数（パッケージ単位で1PR）と数字が食い違って見える問題があった。
これを解消するため、`fetchAllDepscanFindings`（`per_page=200` でページングしながら
現在のフィルタ条件に一致する全件を取得）でデータを丸ごと取得し、
`(repo_full_name, package_name, installed_version)` 単位にクライアント側で
グルーピングしてから表示する。ページネーションもグルーピング後の配列に対して
クライアント側で行う（サーバー側の `page`/`per_page` はこの集約目的にのみ使い、
表示用ページングとしては使わない）。ヘッダーの件数表示は「CVE総数 / パッケージ数」の
両方を出し、どちらの数字を見ているか誤解しないようにしている。

### DEPSCAN ダッシュボードの GitHub ログイン・アクセス制御（Issue #107）
DEPSCAN タブは誰でも閲覧できてしまう状態だったため、任意の GitHub アカウントで OAuth
ログインし、**本人が所有するリポジトリの検知結果のみ**を表示するようにした。UI上のゲート
ではなく、バックエンド側で強制するアクセス制御である点が重要。

**GitHub OAuth（Web Application Flow）:**
`app/auth/router.py` の `/auth/github/login` → GitHub 認可画面へリダイレクト（CSRF対策の
`state` を httpOnly Cookie に保持）→ `/auth/github/callback` で `code` を `access_token` に
交換し、`GET /user` でログインユーザー名（`login`）を取得 → セッション JWT（PyJWT、
`SESSION_SECRET_KEY` で HS256 署名、24時間有効）を発行する。OAuth スコープは `repo`
（GitHub OAuth App は fine-grained PAT のような読み取り専用スコープを持たないため、
本人所有の公開・非公開リポジトリへの読み取りアクセスに必要）。

**セッションJWTの受け渡し方式（Issue #128 → Safari/iOS PWA不具合により再変更）:**
当初はセッションJWTをフロントエンドURLのクエリ文字列（`?depscan_token=...`）に付与して
渡していたが、RFC 9700（OAuth 2.0 Security BCP）がアクセストークン相当の値をURIクエリ
パラメータで渡すことを明示的に禁止しているため（ブラウザ履歴・Referer・プロキシ/サーバー
ログ等への漏えいリスク）、いったん HttpOnly・Secure・SameSite=None の Cookie に変更した
（PR #137）。しかしバックエンド（Render）とフロントエンド（Vercel）はドメインが異なる
クロスサイト構成のため、**Safari の ITP（Intelligent Tracking Prevention）がこの
クロスサイトCookieを既定でブロックし、iOS の PWA（ホーム画面追加アプリ）を含む Safari
系ブラウザでログイン後にセッションが確立されない不具合が実際に発生した**（Chromeは
`SameSite=None; Secure` のクロスサイトCookieを許可するため気づきにくい）。この経緯から、
Cookie方式を撤回し、**使い捨ての交換コード＋Bearerトークン方式**へ変更した:

1. `/auth/github/callback` はセッションJWT本体ではなく、`app/auth/router.py` の
   `_pending_exchange_codes`（インメモリの `{code: (session_token, expires_at)}` 辞書。
   Render は `WEB_CONCURRENCY=1` の単一プロセス運用のためインメモリで問題ない）に
   数十秒（`_EXCHANGE_CODE_TTL_SECONDS`）だけ有効な使い捨てコードを発行し、
   `?depscan_code=...` としてフロントエンドへリダイレクトする
2. フロントエンドは即座に `POST /auth/exchange`（`ExchangeRequest` ボディ `{code}`）へ
   そのコードを渡し、レスポンスJSONボディで `{token, username}` を受け取る
   （`_consume_exchange_code` が pop するため一度しか使えない）
3. 以降はこの `token` を `localStorage` に保存し、`Authorization: Bearer <token>`
   ヘッダーで各エンドポイントを呼ぶ（Cookie不要・ブラウザ非依存）

この方式は、RFC 9700が問題視する「長命なアクセストークンをURLクエリに載せ続ける」
リスクは回避しつつ（コードは数十秒・一度きりしか使えない）、Safari のクロスサイト
Cookie制限の影響を受けない。`app/main.py` の CORS 設定から `allow_credentials=True`
は撤去済み（Cookieに依存しなくなったため不要）。

**`/api/depscan`・`/api/depscan/stats` の認証:**
`app/depscan/router.py` の `_resolve_access` が `X-API-KEY`（既存の共有鍵、絞り込みなしの
フルアクセス。Claude Code 等の既存クライアント向け・SKILL.md の運用を壊さないため維持）
または `Authorization: Bearer <セッションJWT>` を検証する。セッション認証の場合は
`owner` クエリパラメータをログインユーザー名で強制上書きし、`repo` パラメータで
`{username}/` 以外のリポジトリを直接指定しようとした場合は 403 で拒否する
（owner 制限の迂回防止）。

**オンデマンドスキャン（`run_depscan_for_user`）:**
DEPSCAN の毎日クロール（`fetch_and_scan_dependencies`）は `GITHUB_USERNAME`
（baby-feelings）専用のため、任意のアカウントに対応するにはログイン時にその場でスキャン
する必要がある。既存の `_collect_dependencies`/`_build_findings`/`_upsert_findings` は
username/token で汎用化済みのためそのまま再利用し、`run_depscan_for_user` を新設。
毎日クロールとは意図的に独立させており、Slack通知・GitHub Issue自動起票・
`crawler_logs` への記録は**行わない**（第三者のログインのたびにノイズが出ないようにする
ため）。進捗は専用の `UserScan` テーブル（`depscan_user_scans`。username が主キー）に
`running`/`done`/`error` を記録し、`GET /auth/scan-status`（セッションJWT必須）で
ポーリング取得する。

**`_resolve_stale_findings` への `repo_owner_prefix`（クロスユーザー事故防止）:**
`_resolve_stale_findings` はテーブル全体を対象に「今回検知されなかった既存レコード」を
`resolved_at` 済みにする関数。オンデマンドスキャンでこれを無絞り込みのまま呼ぶと、
1ユーザーの少数リポジトリのスキャン結果で baby-feelings 含む無関係な全ユーザーの
未解決 finding を誤って解決済み扱いにしてしまう。これを防ぐため、`repo_full_name LIKE
'{repo_owner_prefix}/%'` で絞り込む任意引数を追加し、`run_depscan_for_user` から
ログインユーザー名を渡している。

**24時間以内は再スキャンしない（`should_rescan_for_user`）:**
当初は毎回ログインの度に必ずスキャンしていたが、リポジトリ数が多いアカウントほど毎回の
ログインで完了まで待たされる問題があった。ユーザーからのフィードバックを受け、直近
`RESCAN_INTERVAL_HOURS`（24時間）以内に完了したスキャンがあれば再スキャンせず DB の
結果をそのまま使うよう変更。実行中（`status == "running"`）の場合は重複起動防止のため
再スキャンしない。エラー終了時は毎回再試行対象とする（一時的な失敗で長時間ブロックしない
ため）。フロントエンド側の変更は不要で、スキャンをスキップした場合は
`/auth/scan-status` が直近の `status: "done"` を即座に返すため自然にローディングなしで
即表示される。SQLite（開発/テスト）は `DateTime(timezone=True)` でも tz 情報を保持せず
naive で返すため、比較前に `tzinfo=UTC` を補完している（PostgreSQL 本番では発生しない
差異）。

**フロントエンド（`DepscanAuthGate.tsx`）:**
未ログイン時は「GitHubでログイン」ボタンを表示。OAuthコールバックからの復帰
（`/?depscan_code=...`）を検出すると、`exchangeAuthCode()` でそのコードをセッション
JWT・ユーザー名と交換し、両方を `localStorage` に保存してURLからは
`history.replaceState` で即座に取り除く（交換失敗＝コード期限切れ・二重使用等の場合は
未ログイン状態のままログイン画面を再表示する）。ログイン後は `/auth/scan-status`
（`Authorization: Bearer <token>`）を4秒間隔でポーリングし、スキャン完了まで
（既にキャッシュがあれば実質即座に）ローディング表示。**ネットワーク瞬断等の
一時的なエラーではログアウトさせず、セッションが実際に無効（401）な場合のみ
ログアウト扱いにする**（`client.ts` の `UnauthorizedError` で区別。ローカル動作確認中に
「fetch失敗のたびに毎回ログアウトしてしまう」不具合を発見し修正済み）。ログアウトは
サーバー側に何も保持していない（JWTはステートレス）ため、`window.confirm` の確認
ダイアログを挟んで `localStorage` をクリアするだけのクライアント側のみの操作。
`App.tsx` は URL に `depscan_code` があれば DEPSCAN タブを自動選択する。

### index.css の CSS カスケードレイヤーに関する注意
`*, *::before, *::after` の余白リセットは必ず `@layer base` の中に書くこと。
`@layer` の外（unlayered）に書くと、CSS カスケードレイヤーの仕様上どんな `@layer utilities`
（Tailwind の padding/margin ユーティリティ含む）よりも優先されてしまい、
`px-*`/`py-*`/`pb-*` 等のユーティリティが軒並み無効化される（過去に実際に発生したバグ）。

### 実行環境表示の日本語化（HealthStatus.tsx）
`/health` の `environment` フィールド（`production`/`development`）はそのまま表示せず、
`ENVIRONMENT_LABELS` で「本番環境」/「開発環境」に変換してから表示する。

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
**単一 cron（`5 19 * * *` / JST 翌 04:05）で KEV → OSV → JVN → DEPSCAN → DEPSOPS を順次実行する構成。**
GitHub Actions 無料プランでは複数 cron の発火が不安定なため、単一 cron に統合した。

| 実行順 | ジョブ | 対象 | 備考 |
|--------|--------|------|------|
| 1 | `wake-up` | Render 起動 | ヘルスチェックでスリープ解除 |
| 2 | `crawl-kev` | `POST /admin/crawl` | KEV フィード取得 |
| 3 | `crawl-osv` | `POST /admin/osv-crawl` | OSV 脆弱性取得（timeout 600s） |
| 4 | `crawl-jvn` | `POST /admin/jvn-crawl` | JVN 脆弱性取得（timeout 600s） |
| 5 | `crawl-depscan` | `POST /admin/depscan-crawl` | 依存ライブラリ脆弱性スキャン（timeout 600s） |
| 6 | `dependabot-ops` | `POST /admin/dependabot-ops` | Dependabot PR 自動運用（DEPSCAN の後段） |

- 各ジョブは `always()` で前段の失敗に関わらず実行される（`wake-up` 成功が前提）
- `workflow_dispatch` で手動実行可能（`target: kev / osv / jvn / depscan / all`）
- GitHub Secrets に `API_KEY`（Render 環境変数と同じ値）を設定すること

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
- **Start Command:** `sh -c "python -m app.core.migrate && uvicorn app.main:app --host 0.0.0.0 --port $PORT"`
  （DBマイグレーション適用の詳細は上記「DBマイグレーションは Alembic で管理する」節を参照）
- **Environment Variables:** `DATABASE_URL`, `API_KEY`, `ENVIRONMENT=production`, `GITHUB_USERNAME`
  （DEPSCAN スキャン対象アカウント。コード側にデフォルト値なし、**未設定だとアプリが起動しない**）、
  `SLACK_WEBHOOK_URL`（任意）、`GITHUB_TOKEN`（任意、DEPSCAN/DEPSOPS 共用の PAT。
  Contents: Read-only + Issues: Write + Pull requests: Write 推奨。未設定時は DEPSCAN/DEPSOPS
  のみエラー終了。Issues: Write が無い場合は Issue自動起票のみ失敗、Pull requests: Write が
  無い場合は DEPSOPS のPRマージ・rebase依頼コメントのみ失敗）。DEPSCAN ダッシュボードの
  GitHub ログイン用に `GITHUB_OAUTH_CLIENT_ID`・`GITHUB_OAUTH_CLIENT_SECRET`（GitHub
  OAuth App の Client ID/Secret）・`SESSION_SECRET_KEY`（セッションJWT署名鍵。
  `python -c "import secrets; print(secrets.token_urlsafe(32))"` 等で生成）も設定する
  （いずれも任意項目・ソフトフェイル方針だが、未設定だと `/auth/*` が 503 を返すのみで
  DEPSCAN タブが機能しない）。`FRONTEND_URL`（既定値: Vercel の本番URL）・
  `API_BASE_URL_FOR_OAUTH`（既定値: Render の本番URL。GitHub OAuth App の
  Authorization callback URL と scheme まで一致させる必要があるため固定値で持つ）は
  値を変える場合のみ設定すればよい

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
