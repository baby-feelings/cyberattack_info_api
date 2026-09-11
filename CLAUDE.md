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
| **デプロイ先** | OCI（Compute VM、Docker Compose。旧Renderから移行済み） |
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
├── main.py                 # FastAPI アプリ・lifespan・スケジューラ登録・ルーター include のみに専念する。
│                           # /admin/* トリガーエンドポイントは持たない（各ドメインの router.py の
│                           # admin_router に定義する。詳細は「/admin/*-crawl はバックグラウンド実行」節）
├── auth/                   # GitHub ログイン（DEPSCAN ダッシュボードのアクセス制御）ドメイン。models 無し
│   ├── router.py           # /auth/github/login・/auth/github/callback・/auth/scan-status
│   ├── github_oauth.py     # GitHub OAuth（Web Application Flow）クライアント
│   └── session.py          # セッショントークン（JWT）の発行・検証
├── core/                   # 横断的インフラ（特定ドメインに属さない）
│   ├── config.py           # Settings（pydantic-settings）・環境変数管理
│   ├── database.py         # SQLAlchemy エンジン（SQLite/PG 切り替え）・get_db
│   ├── auth.py             # X-API-KEY 認証（APIKeyHeader・hmac.compare_digest）
│   ├── background.py       # run_in_background（daemon スレッドでの非同期実行の共通ヘルパー。
│   │                       # KEV/OSV/JVN/DEPSCAN/DEPSOPS の各 /admin/*-crawl から利用）
│   ├── crawler_runner.py   # run_crawler（started_at計測→DBセッション生成→本体処理→crawler_logs記録
│   │                       # →Slack通知→セッションクローズ、という定型処理を一元化する Template Method。
│   │                       # KEV/OSV/JVN の fetch_and_store_* から利用。CrawlCounters で進捗件数を受け渡す）
│   ├── db_utils.py         # DB ユーティリティ（year_month_expr: SQLite/PG 両対応の日付フォーマット）
│   ├── notifications.py    # Slack Webhook 通知（notify_success/notify_error 共通化・エラーサニタイズ）
│   ├── osv_client.py       # OSV API 汎用クライアント（query_versions_batch・fetch_vuln_by_id・
│   │                       # parse_severity 等。app.osv.crawler と app.depscan.crawler の両方が利用）
│   ├── pagination.py       # paginate()（件数カウント・並び替え・offset/limit の定型処理を一元化。
│   │                       # KEV/OSV/JVN/DEPSCAN/DEPSOPS の各一覧APIから利用。フィルタ構築自体は
│   │                       # ドメインごとに異なるため対象外）
│   ├── types.py            # CrawlerType（"KEV"/"OSV"/"JVN"/"DEPSCAN"/"DEPSOPS" の Literal 型）
│   └── schemas.py          # 横断スキーマ（HealthResponse・MonthlyStat・SeverityStat・
│                           # OrmDatetimeModel: ORM オブジェクトの datetime 属性をフィールド列挙なしで
│                           # 自動的に ISO 文字列変換する共通基底クラス。JVN/OSV/DEPSOPS の *Out
│                           # スキーマが継承する）
├── kev/                    # CISA KEV ドメイン
│   ├── models.py           # Vulnerability
│   ├── schemas.py          # VulnerabilityOut 等
│   ├── crawler.py          # CISA KEV クローラー・Upsert ロジック（fetch_and_store_kev は
│   │                       # app.core.crawler_runner.run_crawler 経由で実行される）
│   └── router.py           # router: /api/vulnerabilities エンドポイント（一覧・個別・統計）
│                           # admin_router: POST /admin/crawl（手動トリガー）
├── osv/                    # OSV ドメイン
│   ├── models.py           # OsvVulnerability
│   ├── schemas.py          # OsvVulnerabilityOut 等
│   ├── crawler.py          # OSV クローラー（REST API 方式・10 エコシステム対応、Upsert ロジック）
│   ├── packages.py         # POPULAR_PACKAGES（監視対象パッケージ一覧、ロジックから分離したデータ）
│   └── router.py           # router: /api/osv エンドポイント（一覧・統計）
│                           # admin_router: POST /admin/osv-crawl（手動トリガー）
├── jvn/                    # JVN ドメイン
│   ├── models.py           # JvnVulnerability
│   ├── schemas.py          # JvnVulnerabilityOut 等
│   ├── crawler.py          # JVN クローラー（MyJVN API / RDF-RSS）
│   └── router.py           # router: /api/jvn エンドポイント（一覧・統計）
│                           # admin_router: POST /admin/jvn-crawl（手動トリガー）
├── depscan/                # 依存ライブラリ脆弱性スキャン（DEPSCAN）ドメイン
│   ├── models.py           # DependencyFinding・UserScan（GitHub ログイン経由のオンデマンドスキャン状況）
│   ├── schemas.py          # DependencyFindingOut 等
│   ├── crawler.py          # GitHub 全リポジトリのロックファイルを OSV API とリアルタイム照合
│   ├── user_scan.py        # run_depscan_for_user/get_user_scan_status/should_rescan_for_user
│   │                       # （GitHub ログイン経由のオンデマンドスキャン）
│   ├── router.py           # router: /api/depscan エンドポイント（一覧・統計。X-API-KEY またはセッション
│   │                       # トークンの二重認証）
│   │                       # admin_router: POST /admin/depscan-crawl（手動トリガー）
│   ├── github_client.py    # GitHub API クライアント（リポジトリ一覧・ツリー・ファイル取得）
│   └── parsers/            # 10 エコシステム分のロックファイルパーサー
├── depsops/                # Dependabot PR 自動運用（DEPSOPS）ドメイン
│   ├── models.py           # DependabotPrLog（判定した PR 1件1行の履歴。action=merged/flagged・reason）
│   ├── schemas.py          # DependabotPrLogOut 等
│   ├── runner.py           # crawler.py 相当。run_dependabot_ops（判定・マージ・Slack通知・
│   │                       # DependabotPrLog への永続化・保持期間超過分の削除）
│   ├── router.py           # router: GET /api/depsops（判定履歴一覧。リポジトリ・action でフィルタ可能）
│   │                       # admin_router: POST /admin/dependabot-ops（手動トリガー）
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
├── core/                   # DB エンジン・Slack 通知・run_in_background・run_crawler・
│                           # paginate・migrate・OrmDatetimeModel テスト
├── kev/                    # KEV クローラー・API テスト
├── osv/                    # OSV クローラー・API テスト
├── jvn/                    # JVN クローラー・API テスト
├── depscan/                # DEPSCAN クローラー・API・パーサーテスト
├── depsops/                # DEPSOPS 判定ロジック・DependabotPrLog永続化・API・
│                           # GitHub操作・Slack通知テスト
└── crawler_logs/           # クローラーログ API テスト

dashboard/               # Vercel デプロイの React ダッシュボード
                         # CISA KEV・OSV（Pub 含む 10 エコシステム・180 日表示）・JVN・
                         # DEPSCAN（GitHub ログイン必須。本人所有リポジトリのみ表示。到達可能性
                         # 列を含む）を画面下部固定タブ（4つ。DEPSOPS 専用タブは作らない）で
                         # 切り替え表示。Dependabot 運用状況＝DEPSOPS の判定履歴は DEPSCAN タブ内の
                         # ボタンから開く全画面モーダルとして統合
                         #
                         # src/components/{kev,osv,jvn,depscan}/ 配下に、各 Panel から切り出した
                         # 行コンポーネント（KevRow/OsvRow/JvnRow/DepscanGroupRow）・グラフコンポーネント
                         # （VendorBarChart/EcosystemBarChart/RepoBarChart/DepsOpsRepoBarChart）・
                         # grouping.ts（DEPSCAN 集約ロジック）・depsopsGrouping.ts（DEPSOPS
                         # リポジトリ別未解決件数集計）・DependabotOpsModal（DEPSOPS 判定履歴。
                         # 全画面モーダル、開いたときのみ GET /api/depsops を取得）を配置

alembic/                 # DBスキーマのマイグレーション管理
├── env.py               # Base.metadata・全モデル import（新規ドメイン追加時はここに追記必須）・
│                       # DATABASE_URL 設定
└── versions/            # マイグレーションスクリプト（Git管理下。app.core.migrate から適用）

.github/
├── dependabot.yml   # Dependabot（pip: / ・npm: /dashboard、週次で依存更新PRを自動作成）
└── workflows/
    ├── ci.yml           # CI: ruff → mypy → pytest（PR 時・Python 3.10/3.11 matrix）
    ├── deploy.yml       # CD: Vercel デプロイ（main マージ時。バックエンドはOCIへ手動デプロイ）
    └── daily-crawl.yml  # 毎日クロール: 単一 cron(UTC 19:05) で KEV → OSV → JVN → DEPSCAN → DEPSOPS を順次実行

Dockerfile                  # バックエンドのコンテナイメージ定義（OCI上でdocker composeがビルド）
deploy/                     # OCIデプロイ関連（下記「OCIへの移行」節参照）
├── deploy_to_oci.ps1       # SCP転送 + docker compose up -d --build を行うデプロイスクリプト
├── docker-compose.yml      # api-prod・caddy・prometheus・grafana・node-exporter
├── Caddyfile                # リバースプロキシ設定（BACKEND_DOMAIN/GRAFANA_DOMAINをHTTPS化）
├── .env.example / prometheus.yml.example  # 秘密情報を含む実ファイル（.env/prometheus.yml）はgit管理外
└── grafana/                 # データソース・ダッシュボードの自動プロビジョニング設定
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
`PUBLIC_API_KEY` の値のみを設定する。`/admin/*`（各ドメインの `router.py` の `admin_router`）は
従来通り `require_api_key`（`API_KEY` のみ許可）のままで、`PUBLIC_API_KEY` では通らない。
DEPSCAN（`app/depscan/router.py`）はダッシュボードから `X-API-KEY` を一切送らず GitHub
ログインのセッショントークンのみを使うため、この分離の対象外（`_resolve_access` は
引き続き `API_KEY` のみを直接比較する）。Claude Code 等の既存クライアントは引き続き
`API_KEY` を使えばよく、SKILL.md の運用は変わらない。

### 実装Tips
- APIキー比較は `hmac.compare_digest` で定数時間比較する（タイミング攻撃対策）
- ORM定義は `Mapped`/`mapped_column` スタイル（`Column` 直書きは mypy と非互換。`pyproject.toml` に `sqlalchemy.ext.mypy.plugin` 設定済み）
- `Settings()` の呼び出しには `# type: ignore[call-arg]`（mypy が `.env` からの注入を認識できないため）
- ヘルスチェック等で `db_gen` を使う場合は try の前で `None` 初期化してから `finally` でガードする（`UnboundLocalError` 対策）

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

### クローラー実行の共通オーケストレーション（crawler_runner.py）
KEV/OSV/JVN の `fetch_and_store_*` が個別に持っていた「started_at計測 → DBセッション生成 →
本体処理 → crawler_logs記録 → Slack通知 → DBセッションクローズ」という定型処理を
`app.core.crawler_runner.run_crawler`（Template Method）に一元化している。各クローラーは
取得・Upsert・保持期間削除といったドメイン固有の処理のみを `body(db, counters)` 関数として
`run_crawler` に渡す。進捗件数は `CrawlCounters`（dataclass）で受け渡し、`body` が処理の進行に
応じて `counters.inserted`/`updated`/`deleted` を加算する。**エラー発生時もその時点までの
counters の値を crawler_logs に反映する**（OSV はエコシステム単位で処理を継続する既存挙動が
あり、途中で例外が発生してもそれまでに成功した件数を記録する。KEV/JVN はエラー時点で
件数がまだ確定していないため、従来通り 0/0/0 で記録される）。

### ORM オブジェクトの datetime 自動変換（OrmDatetimeModel、core/schemas.py）
素の `from_attributes=True` では、フィールド型を `str` と宣言した属性に ORM 側の datetime 値を
そのまま渡すとバリデーションエラーになる。これを避けるため、JVN/OSV/DEPSOPS の出力スキーマは
かつて「ORM オブジェクトから手動で dict を構築し、日時だけ isoformat() してから
super().model_validate() へ委譲する」実装を個別に持っていたが、フィールドを手動列挙する方式は
新フィールド追加時に列挙し忘れるとサイレントに None へフォールバックしてしまう（実際に
fetched_at 追加時にこの事故が発生し、本番で常に null を返す不具合になった）。
`OrmDatetimeModel`（`app.core.schemas`）は列挙をやめ、Pydantic が認識している宣言済み
フィールド一覧（`cls.model_fields`）を動的に読んで ORM オブジェクトから値を取り出し、
datetime 型の属性だけ自動変換する。`JvnVulnerabilityOut`/`OsvVulnerabilityOut`/
`DependabotPrLogOut` はこれを継承しており、新フィールドを追加するだけで自動的に対応する。

### 一覧APIのページネーション共通化（pagination.py）
`list_vulnerabilities`/`list_osv`/`list_jvn`/`list_depscan`/`list_depsops` がそれぞれ持っていた
「`query.count()` → offset算出 → `order_by`/`offset`/`limit` を適用して取得」という定型処理を
`app.core.pagination.paginate(query, page, per_page, order_by)` に一元化している。フィルタ条件
の構築（検索キーワード・重要度・エコシステム等の絞り込み）はドメインごとに大きく異なるため
対象外とし、真に共通していたページネーション部分のみを抽出した。

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
対し、意図せず alembic の管理外操作が走ってテストが壊れるのを避けるため）。`Dockerfile`
の `CMD`（`python -m app.core.migrate && uvicorn ...`。旧Renderの Start Command と
同じ順序を踏襲）として、アプリ起動前に明示的に呼び出す運用とする。

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

### 来歴・鮮度・差分API（Issue #129・KEV/OSV/JVN共通）
「source_modified_at と fetched_at を区別し、差分取得（updated_since）を提供する」
という要件に対応し、KEV/OSV/JVNに以下を追加した:

- **`fetched_at`**: クローラーが取得元で最後に存在確認した日時。既存の`updated_at`
  （内容が実際に変わった時だけ更新）とは異なり、**変更が無かった回のクロールでも毎回
  更新**する（鮮度の可視化用）。`changed`判定の等値比較には含めない（含めると常に
  「変更あり」と誤判定するため）
- **`updated_since`クエリパラメータ**: `fetched_at`は毎回更新されフィルタに使うと
  実質全件を返してしまうため、内容が実際に変わった時だけ動く`updated_at`を条件に使う
- **OSVの`withdrawn_at`**: OSVスキーマの`withdrawn`フィールドをパースして保存
  （KEV・JVNには撤回の概念が無いため対象外）

SQLiteは`CURRENT_TIMESTAMP`が秒精度（マイクロ秒無し）のため、`updated_since`のテストで
同一秒内のinsertがcutoff比較に負けるレースコンディションに注意（`updated_at`を明示的な
固定値へ強制更新してから検証する。`test_*_updated_since_filter`参照）。

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

### DEPSCAN のリポジトリ内未解決 findings が0件になったら Issue を自動クローズする
`app.depscan.crawler._close_resolved_repo_issues` が、DEPSCAN の再スキャンで「そのリポジトリの
未解決 finding が実際に0件になったこと」を確認できたタイミングで Open な DEPSCAN Issue を
自動的にクローズする。トリガーを **DEPSCAN の再スキャン検証後**とし、DEPSOPS の PR マージ
直後に即座にクローズしない設計（マージしただけでは本当に脆弱性が解消されたか未検証のため）。
`_resolve_stale_findings` が返す `(解決件数, 今回1件以上解決した repo_full_name の集合)` の
後者（`affected_repos`）を候補リポジトリとして受け取り、そのリポジトリに絞って「未解決
finding が本当に0件か」を再度 DB に問い合わせてから判定する（無関係なリポジトリへの
無駄な GitHub API 呼び出しを避けるため）。Issue 本文に列挙された個々の CVE を突き合わせる
のではなく、「未解決 finding が0件か」というシンプルな条件のみで判定する。クローズ前に
`add_issue_comment` で解決を報告するコメントを追加してから `close_issue`（PATCH
`state=closed`）を呼ぶ。GitHub API 呼び出し失敗はリポジトリ単位で握りつぶし、DEPSCAN
全体の成功可否には影響させない（Issue 起票と同じ方針）。

### DEPSCAN の到達可能性（reachability）ヒューリスティック判定
「脆弱な依存が存在すること」と「実際に到達・悪用可能であること」は別問題（依存スキャナの
偽陽性の主因は到達不能コードの検知）。`app.depscan.reachability`が、脆弱なパッケージが
リポジトリのソースコード内で実際に**import/require/useされているか**（importレベルのみ。
関数呼び出しレベルの解析はスコープ外）を判定し、`DependencyFinding.reachability`
（`"reachable"`/`"unreachable"`/`"unknown"`）へ格納する。対応は全10エコシステム。
パッケージ名からソース内識別子への変換精度はエコシステムにより差が大きく、Maven・
Packagist・Hexは最も精度が低いbest-effort。`get_source_files`が対象リポジトリの
ソースを取得（`_MAX_SOURCE_FILES=200`件・`_MAX_SOURCE_FILE_SIZE=300_000`バイト上限）し、
`_apply_reachability`がリポジトリ×エコシステムごとに1回だけ使い回す。取得失敗は
`"unknown"`のまま残し、DEPSCAN全体の成功可否には影響させない。再スキャンのたびに
既存レコードの`reachability`も再計算・上書きする。

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
`Dependabot alerts`・`Dependabot security updates` の3点）。
**Dependabot PR は内容を確認せず自動マージしないこと。** メジャーバージョンアップは非互換な
依存衝突を起こしうる（実例: `typescript` 6.0.3→7.0.2 が `typescript-eslint` の peer 依存と
衝突しVercelビルドが失敗、対応するまで `~6.0.3` に固定）。マージ前にCIに加え、フロントエンド
変更はVercelプレビューデプロイの完了を確認する。

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
**安全性が高いものだけを自動マージする**運用層。`POST /admin/dependabot-ops`から
`run_dependabot_ops`を呼ぶ。手動運用で半日問題ないことを確認した後、他クローラーと
同様に`DEPSOPS_CRON_HOUR_UTC`（既定UTC 23:00=JST 8:00、DEPSCANの後段）で自動実行する
ようにした。コンフリクトでマージできなかったPRは、翌日以降リベースが完了していれば
自動的に再判定・マージされる（複数日にまたがる自己修復）。

**判定ロジック**（`_process_pr`、上から順に評価）:
1. `mergeable_state == "dirty"`（コンフリクト）→ `@dependabot rebase`をコメントしflagged
2. 対象リポジトリにCI（`.github/workflows`）が無い → 常にflagged（安全性を検証する
   手段が無いため）
3. `classify_bump`の判定が`"major"`または`"unknown"`（`from X to Y`を抽出できない
   grouped PR等）→ flagged。**0.x系はminorの変化もmajor扱い**（semverの慣習）
4. `mergeable_state != "clean"`（CI失敗・レビュー待ち等）→ flagged
5. いずれにも該当しない（マイナー/パッチ・CIあり・コンフリクトなし）→ 自動マージ

マージ・flaggedいずれも毎回Slack通知（監査性優先、0件同士のみスキップ）。判定結果は
`DependabotPrLog`テーブルへ1PR1行で永続化し（Slack通知は実行時点のスナップショットの
みで履歴を持たないため）、`GET /api/depsops`で参照する。ダッシュボードにはDEPSOPS専用
タブは作らず、DEPSCANタブ内のボタンから開く全画面モーダル（`DependabotOpsModal.tsx`）
として統合している。

**`is_security_update`（セキュリティ更新/バージョン更新の判定）**: `list_open_
dependabot_alerts`でリポジトリのOpenなDependabot alert対象パッケージ名を取得し、PR
タイトルと単語境界一致で照合する（GitHub自身のalertsと照合する方式、DEPSCAN自前DBとは
照合しない）。`GITHUB_TOKEN`に**Dependabot alertsの読み取り権限**が必要（classic PAT:
`security_events`スコープ / fine-grained PAT:「Dependabot alerts: Read-only」）。権限が
無い場合は`null`（不明）のまま記録され、**過去の記録は遡って再判定されない**（履歴を
積み増すだけのテーブルのため）。

**`compatibility_badge_url`**: Dependabotがexact version bumpのPR本文に埋め込む
「Compatibility score」バッジ画像URLを正規表現で抽出し保存する。GitHub側に数値取得APIは
無いため、ダッシュボードは独自判定をせずURLをそのまま`<img>`表示する。

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

### /admin/*-crawl はバックグラウンド実行（202 即時返却）・各ドメインの router.py に定義する
`/admin/crawl`（KEV）・`/admin/osv-crawl`・`/admin/jvn-crawl`・`/admin/depscan-crawl`・
`/admin/dependabot-ops` は即座に 202 Accepted を返し、`app.core.background.run_in_background`
（daemon スレッドで実行し、例外はログに記録するだけで呼び出し元へは伝播させない共通ヘルパー）で
バックグラウンド実行する（旧Render無料プランのリクエストタイムアウト対策として導入した設計だが、
即時返却自体はOCI移行後も有用なため維持）。結果は `/api/crawler-logs` で確認する。
OSV・JVN は `?days=N` クエリパラメータで取得対象日数を指定可能（初回バックフィル用）。

各エンドポイントは対応するドメインの `app/{kev,osv,jvn,depscan,depsops}/router.py` に、
`/api/xxx` prefix 付きの通常 `router` とは別に **prefix なし・`Security(require_api_key)`
で保護する `admin_router`** として定義する（`/api/vulnerabilities` 等の prefix に
`/admin/crawl` が巻き込まれてしまうのを避けるため）。`app/main.py` はこれらの router と
admin_router をすべて `include_router` するだけで、エンドポイント定義自体は持たない
（include_router 呼び出しと lifespan・スケジューラ配線に専念する）。

### ダッシュボードのタブ切り替え UI（App.tsx）
KEV / OSV / JVN / DEPSCAN の 4 データソースは、画面下部固定のタブバーで切り替え表示する構成
（縦並び表示ではない）。DEPSOPS（Dependabot 運用状況）に専用タブは作らず、DEPSCAN タブ内の
ボタンから開く全画面モーダルとして統合している（詳細は「DEPSOPS」節参照）。
`TabKey` / `TABS` 定数と `activeTab` state で選択中セクションのみを条件レンダリングし、
サーバー稼働状況（`HealthStatus`）とエラーバナーは全タブ共通で常に表示する。
タブには `role="tablist"/"tab"/"tabpanel"` と `aria-selected`/`aria-controls`/`aria-labelledby` を付与済み。

### KevPanel/OsvPanel/JvnPanel の共通パーツ（VulnPanelParts.tsx）とドメイン別サブコンポーネント
`dashboard/src/components/shared/VulnPanelParts.tsx` に、各パネルで共通の
`SeverityBadge`・`ChartCard`・`SeverityPieChart`・`MonthlyBarChart`・`TableLoadingSkeleton`・
`EmptyState`・`Pagination`・`SeverityFilterButtons`・`SearchBox`・`SortSelector` を切り出し済み。
深刻度の値・配色（OSV: CRITICAL/HIGH/MEDIUM/LOW、JVN: High/Medium/Low）はドメイン固有のため
`classMap`/`colorMap` として呼び出し側から渡す。

行コンポーネント（`KevRow`/`OsvRow`/`JvnRow`）とグラフコンポーネント
（`VendorBarChart`/`EcosystemBarChart`）はドメイン固有のため、`DepscanGroupRow`/`RepoBarChart`
（`components/depscan/`）に倣い `components/{kev,osv,jvn}/` 配下に切り出している。深刻度バッジの
配色（`SEVERITY_CLS`）は各 Panel の重要度フィルターボタンでも使うため Panel 側に残し、Row
コンポーネントには `severityClassMap` として props で渡す（`SeverityBadge`/`SeverityFilterButtons`
と同じ「呼び出し側が classMap を渡す」パターン）。Recharts の Tooltip `formatter` は jsdom 上で
ホバーをシミュレートしてもテストから呼び出されないため、`formatVendorTooltipValue` のように
名前付き関数として切り出しテストから直接呼び出す（表示内容は不変）。

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
任意の GitHub アカウントで OAuth ログインし、**本人が所有するリポジトリの検知結果のみ**
表示する（UIゲートではなくバックエンド側で強制するアクセス制御）。

- **OAuthフロー**: `/auth/github/login` → GitHub認可（scope `repo`）→
  `/auth/github/callback` で `code` を `access_token` に交換しログインユーザー名取得 →
  セッションJWT（PyJWT、`SESSION_SECRET_KEY`でHS256署名、24時間有効）発行
- **セッションJWTの受け渡しは使い捨て交換コード方式**: JWT本体をURLクエリに載せるのは
  RFC 9700（OAuth 2.0 Security BCP）違反、Cookie方式はSafari ITPがクロスサイトCookieを
  ブロックしiOS PWAでログインできない不具合が実際に発生した（過去2回の設計変更を経て
  現方式に到達）。現在は `/auth/github/callback` が数十秒だけ有効な使い捨て交換コードを
  `?depscan_code=...` でフロントエンドへ渡し、フロントエンドが即座に
  `POST /auth/exchange` でセッションJWTと交換、以降 `Authorization: Bearer <token>` を
  `localStorage` 経由で使う（Cookie不要）
- **`/api/depscan`系の認証**: `_resolve_access` が `X-API-KEY`（フルアクセス、Claude Code
  等向け）または `Authorization: Bearer <セッションJWT>` を検証。セッション認証時は
  `owner` を強制的にログインユーザー名で上書きし、他人のリポジトリを`repo`パラメータで
  直接指定しても403（owner制限の迂回防止）
- **オンデマンドスキャン**（`run_depscan_for_user`）: 毎日クロールは`GITHUB_USERNAME`
  専用のため、任意アカウントはログイン時にその場でスキャンする。Slack通知・Issue起票・
  `crawler_logs`記録は行わない（第三者ログインのたびのノイズを避けるため）。進捗は
  `UserScan`テーブルに記録し`/auth/scan-status`でポーリング取得。直近24時間以内に完了
  済みなら再スキャンをスキップする（`should_rescan_for_user`）
- **`_resolve_stale_findings`のクロスユーザー事故防止**: 無絞り込みで呼ぶと1ユーザーの
  スキャン結果で他ユーザーの未解決findingを誤って解決済み扱いにしてしまうため、
  `repo_owner_prefix`引数でそのユーザーのリポジトリのみに絞り込む
- **フロントエンド**（`DepscanAuthGate.tsx`）: ネットワーク瞬断等の一時的エラーでは
  ログアウトさせず、セッションが実際に無効（401）な場合のみログアウト扱いにする
  （`UnauthorizedError`で区別。当初「fetch失敗のたびにログアウトする」不具合があった）

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
teardown時は `test_engine.dispose()` でコネクションを解放してから `os.remove("test.db")` する（`OSError` は無視）。dispose せず削除すると Windows ではファイルロックで失敗する。

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

- Vercel デプロイ: `VERCEL_TOKEN` / `VERCEL_ORG_ID` / `VERCEL_PROJECT_ID` を設定（未設定時はスキップ）
- **注意:** `secrets` コンテキストは `if` 条件式で直接参照できないため、`run` ブロック内のシェル分岐で判定する
- バックエンド（FastAPI）は Render から OCI へ移行済み（下記「OCI への移行」節）。
  GitHub Actions からの自動デプロイは無く、`deploy/deploy_to_oci.ps1` を都度手動実行する運用

### 毎日クロール（daily-crawl.yml）
OCI移行前はRender Freeプランのスリープ対策として導入したが、OCI移行後は「ネットワーク障害等で
APSchedulerが不発火だった場合の二重バックアップ」として維持している（`wake-up`ジョブは
実質ヘルスチェックのみで、スリープ解除の意味は無くなった）。
**単一 cron（`5 19 * * *` / JST 翌 04:05）で KEV → OSV → JVN → DEPSCAN → DEPSOPS を順次実行する構成。**
GitHub Actions 無料プランでは複数 cron の発火が不安定なため、単一 cron に統合した。

| 実行順 | ジョブ | 対象 | 備考 |
|--------|--------|------|------|
| 1 | `wake-up` | ヘルスチェック | OCI移行後は死活監視のみ（スリープ解除の意味は無い） |
| 2 | `crawl-kev` | `POST /admin/crawl` | KEV フィード取得 |
| 3 | `crawl-osv` | `POST /admin/osv-crawl` | OSV 脆弱性取得（timeout 600s） |
| 4 | `crawl-jvn` | `POST /admin/jvn-crawl` | JVN 脆弱性取得（timeout 600s） |
| 5 | `crawl-depscan` | `POST /admin/depscan-crawl` | 依存ライブラリ脆弱性スキャン（timeout 600s） |
| 6 | `dependabot-ops` | `POST /admin/dependabot-ops` | Dependabot PR 自動運用（DEPSCAN の後段） |

- 各ジョブは `always()` で前段の失敗に関わらず実行される（`wake-up` 成功が前提）
- `workflow_dispatch` で手動実行可能（`target: kev / osv / jvn / depscan / all`）
- `API_BASE_URL`（ワークフロー内の env）は OCI インスタンスのドメイン
  （`https://168.138.213.240.nip.io`）。インスタンスを作り直した場合はここも更新すること
- GitHub Secrets に `API_KEY`（OCI の `.env.production` と同じ値）を設定すること

---

## デプロイ構成

| 役割 | サービス | 備考 |
|------|---------|------|
| **アプリサーバー** | OCI（Compute VM、Ampere A1） | Docker Compose、手動デプロイ（`deploy/deploy_to_oci.ps1`）。旧Renderから移行済み |
| **データベース** | Neon（PostgreSQL 16） | Free プラン、0.5 GB。OCI移行後も継続利用（DB移行なし） |
| **ダッシュボード** | Vercel | React（`dashboard/` ディレクトリ）。GitHub Actions（`deploy.yml`）経由で自動デプロイ |
| **CI/CD** | GitHub Actions | PR → CI → Merge → Vercel自動デプロイ。バックエンドは手動デプロイ |

### OCI の設定（旧Render設定からの移行、詳細は「OCIへの移行」節参照）
- **稼働方式:** Docker Compose（`deploy/docker-compose.yml`。`api-prod`・`caddy`・
  `prometheus`・`grafana`・`node-exporter`）。DBマイグレーションはコンテナ起動時に
  `Dockerfile`の`CMD`（`python -m app.core.migrate && uvicorn ...`）で自動適用する
  （Renderの Start Command と同じ順序を踏襲）
- **Environment Variables（`.env.production`、OCIへ転送）:** `DATABASE_URL`, `API_KEY`,
  `ENVIRONMENT=production`, `GITHUB_USERNAME`
  （DEPSCAN スキャン対象アカウント。コード側にデフォルト値なし、**未設定だとアプリが起動しない**）、
  `SLACK_WEBHOOK_URL`（任意）、`GITHUB_TOKEN`（任意、DEPSCAN/DEPSOPS 共用の PAT。
  Contents: Read-only + Issues: Write + Pull requests: Write 推奨。未設定時は DEPSCAN/DEPSOPS
  のみエラー終了。Issues: Write が無い場合は Issue自動起票のみ失敗、Pull requests: Write が
  無い場合は DEPSOPS のPRマージ・rebase依頼コメントのみ失敗。DEPSOPS の `is_security_update`
  判定には別途 Dependabot alerts の読み取り権限が必要〈classic PAT なら `security_events`
  スコープ、fine-grained PAT なら「Dependabot alerts: Read-only」〉。無い場合は判定結果が
  `null`〈不明〉のまま記録されるのみで DEPSOPS 本来のマージ判定には影響しない）。DEPSCAN ダッシュボードの
  GitHub ログイン用に `GITHUB_OAUTH_CLIENT_ID`・`GITHUB_OAUTH_CLIENT_SECRET`（GitHub
  OAuth App の Client ID/Secret）・`SESSION_SECRET_KEY`（セッションJWT署名鍵。
  `python -c "import secrets; print(secrets.token_urlsafe(32))"` 等で生成）も設定する
  （いずれも任意項目・ソフトフェイル方針だが、未設定だと `/auth/*` が 503 を返すのみで
  DEPSCAN タブが機能しない）。`FRONTEND_URL`（既定値: Vercel の本番URL）・
  `API_BASE_URL_FOR_OAUTH`（既定値・現在値ともに OCI インスタンスの URL
  `https://168.138.213.240.nip.io`。GitHub OAuth App の Authorization callback URL
  と scheme まで一致させる必要があるため固定値で持つ。インスタンスを作り直した場合は
  `.env.production`・コード側デフォルト値〈`app/core/config.py`〉・GitHub OAuth Appの
  callback URL の3箇所を同時に更新すること）・`METRICS_API_KEY`（運用監視、任意）は
  値を変える場合のみ設定すればよい

### GitHub Secrets の設定

| Secret 名 | 説明 |
|-----------|------|
| `API_KEY` | OCI の `.env.production` に設定した API キーと同じ値（daily-crawl.yml 用） |

---

### OCI への移行（Issue #165、完了）

Render無料プランはコールドスタート・スリープがあり、`/admin/*-crawl`のバックグラウンド
処理がデプロイ再起動で強制終了される事故（DEPSCANスキャンが`running`のまま取り残される
障害、PR #152）の原因になっていた。`crypto_forecast`（https://github.com/baby-feelings/
crypto_forecast）で実績のあるOCI Always Free + Docker Compose + Caddy構成を、本プロジェ
クト専用の新規別インスタンスに適用し常時稼働化した。DBはNeonを継続利用（DB移行なし）。
デプロイは`deploy/deploy_to_oci.ps1`を都度手動実行する運用（GitHub Actions経由の自動
デプロイは廃止）。

**現状**: インスタンス作成・デプロイ・監視導入（Issue #167）・カットオーバー・キー
ローテーションまで完了。稼働先は`cyberattack-info-api`インスタンス（Ampere A1、
1 OCPU/6GB、Ubuntu 24.04 aarch64、IP `168.138.213.240`）。Renderは安全のためすぐには
削除せず、Suspend状態でしばらく保持する。

**運用上の注意点**:
- crypto_forecast（`crypto-bot-server`）とAlways FreeのAmpere A1枠（合計4 OCPU/24GB）
  を共有するため、新規インスタンス作成前に残り容量を確認すること。現在は
  crypto_forecast側を2 OCPU/12GBへリサイズして空きを確保している
  （リサイズはインスタンスの一時停止が必要）
- ポート80/443の開放はOCIセキュリティリストとインスタンスOS側の両方が必要。
  **本インスタンスはufwではなくiptables + iptables-persistentで管理されている**
  （crypto_forecastと異なる点）。`sudo iptables -I INPUT <ufwの手前> -p tcp -m state
  --state NEW -m tcp --dport <port> -j ACCEPT` → `sudo netfilter-persistent save`
- `API_BASE_URL_FOR_OAUTH`はGitHub OAuth Appのcallback URLと一致させる必要がある。
  インスタンスを作り直した場合は`.env.production`・`app/core/config.py`のデフォルト値・
  GitHub OAuth Appのcallback URLの3箇所を同時に更新すること

**教訓（`.env.production`取り扱いの事故）**: 秘密情報ファイルを`cat`/`awk -F=`等の
全内容表示コマンドで確認すると値が露出する（YAML等`=`を含まない行はそのまま出力される
ため`awk -F=`でも防げない）。キー名だけの確認には`grep -oE '^[A-Z_]+='`、行数確認には
`grep -c '^KEY='`を使う。ファイルへの追記前は末尾に改行があるか確認する（無いと追記が
既存行に連結される）。`python3`はこの環境ではWindowsストアの無効なスタブのため使わず
`python`を使う。

**教訓（`.env.prod`と`.env.production`の二重管理事故）**: OCI移行当初、ローカル開発と
同じ`.env.production`とは別に、OCI転送専用の`.env.prod`という似た名前のファイルを
用意していた。しかしその後の秘密情報ローテーション・GitHub OAuth設定はすべて
`.env.production`側にのみ適用され、`.env.prod`への反映が漏れたまま気づかず、
後日`.env.prod`をそのままOCIへ再デプロイした際に本番の`GITHUB_OAUTH_CLIENT_ID`等が
空になりログイン不能になる障害が発生した。原因究明後、`.env.prod`を廃止し
`.env.production`を唯一の本番設定ファイルとしてそのままOCIへ転送する構成に統一した
（`deploy/docker-compose.yml`の`env_file`・`deploy/deploy_to_oci.ps1`参照）。
同じ内容を持つはずのファイルを2つ運用しないこと（DRY原則）。

### 運用監視（Prometheus + Grafana、Issue #167）
「クローラーが実際に成功しているか」を可視化することを主眼に、crypto_forecastの構成を
本APIの実態（スケジュール実行される5種のクローラー）に合わせて設計し直した。

- **`app/core/metrics.py`**: `Authorization: Bearer`（`METRICS_API_KEY`、未設定時は
  503でopt-in）で保護する`/metrics`エンドポイント。クローラー実行結果を
  `crawler_last_run_success`/`_timestamp_seconds`/`_duration_seconds`/`_inserted`/
  `_updated`/`_deleted`のGauge（`crawler_type`ラベル付き）として公開する。Counterでは
  なくGaugeなのは「直近の実行結果」を一目で見たいため。`record_crawler_run()`の呼び出し
  元は`app.crawler_logs.writer.write_crawler_log`1箇所のみ（全クローラー共通の記録経路）
- **`deploy/docker-compose.yml`**: `prometheus`（30秒間隔でスクレイプ、`127.0.0.1`のみ
  バインド）・`node-exporter`（filesystem+meminfoコレクタのみ）・`grafana`（Caddy経由で
  `GRAFANA_DOMAIN`にHTTPS公開）を追加。**`node-exporter`の`/:/host:ro,rslave`マウントは
  Windows Docker Desktop（WSL2）ではエラーになる**が、OCI（ネイティブLinux）では問題ない
  （ローカル検証時は`docker compose up -d --no-deps prometheus grafana`で除外する）
- **`deploy/grafana/`**: `provisioning/datasources/prometheus.yml`で`uid: prometheus_ds`
  を固定してデータソースを自動登録する（自動生成uidだと再プロビジョニングのたびに変わり
  ダッシュボードJSON側の参照が壊れるため）。ダッシュボード名は「サイバー攻撃情報API」
- **Grafana管理者ユーザー名の変更**: `GF_SECURITY_ADMIN_USER`は初回シードのみに効くため、
  既存adminユーザーの改名にはGrafana API（`PUT /api/users/:id`、`{"login": "新名前"}`）
  が必要（`docker-compose.yml`のコメント参照）

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
