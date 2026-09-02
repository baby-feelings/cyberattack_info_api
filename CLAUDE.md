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
│                           # /admin/dependabot-ops（スケジューラ登録なし・手動トリガーのみ）
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
│   ├── models.py           # DependencyFinding
│   ├── schemas.py          # DependencyFindingOut 等
│   ├── crawler.py          # GitHub 全リポジトリのロックファイルを OSV API とリアルタイム照合
│   ├── router.py           # /api/depscan エンドポイント（一覧・統計）
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
├── core/                   # DB エンジン・Slack 通知テスト
├── kev/                    # KEV クローラー・API テスト
├── osv/                    # OSV クローラー・API テスト
├── jvn/                    # JVN クローラー・API テスト
├── depscan/                # DEPSCAN クローラー・API・パーサーテスト
├── depsops/                # DEPSOPS 判定ロジック・GitHub操作・Slack通知テスト
└── crawler_logs/           # クローラーログ API テスト

dashboard/               # Vercel デプロイの React ダッシュボード
                         # CISA KEV・OSV（Pub 含む 10 エコシステム・180 日表示）・JVN を
                         # 画面下部固定タブで切り替え表示

.github/
├── dependabot.yml   # Dependabot（pip: / ・npm: /dashboard、週次で依存更新PRを自動作成）
└── workflows/
    ├── ci.yml           # CI: ruff → mypy → pytest（PR 時・Python 3.10/3.11 matrix）
    ├── deploy.yml       # CD: Render Deploy Hook トリガー（main マージ時）
    └── daily-crawl.yml  # 毎日クロール: 単一 cron(UTC 19:05) で KEV → OSV → JVN → DEPSCAN を順次実行
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
`app.depsops.runner.run_dependabot_ops` を呼ぶ。他クローラーと異なり
**APScheduler にも GitHub Actions にも一切スケジュール登録していない
（意図的な設計。手動トリガーのみ）**。安全に運用できると分かった段階で自動化を
検討する前提。

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
**単一 cron（`5 19 * * *` / JST 翌 04:05）で全 4 クローラーを順次実行する構成。**
GitHub Actions 無料プランでは複数 cron の発火が不安定なため、単一 cron に統合した。

| 実行順 | ジョブ | 対象 | 備考 |
|--------|--------|------|------|
| 1 | `wake-up` | Render 起動 | ヘルスチェックでスリープ解除 |
| 2 | `crawl-kev` | `POST /admin/crawl` | KEV フィード取得 |
| 3 | `crawl-osv` | `POST /admin/osv-crawl` | OSV 脆弱性取得（timeout 600s） |
| 4 | `crawl-jvn` | `POST /admin/jvn-crawl` | JVN 脆弱性取得（timeout 600s） |
| 5 | `crawl-depscan` | `POST /admin/depscan-crawl` | 依存ライブラリ脆弱性スキャン（timeout 600s） |

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
- **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- **Environment Variables:** `DATABASE_URL`, `API_KEY`, `ENVIRONMENT=production`, `GITHUB_USERNAME`
  （DEPSCAN スキャン対象アカウント。コード側にデフォルト値なし、**未設定だとアプリが起動しない**）、
  `SLACK_WEBHOOK_URL`（任意）、`GITHUB_TOKEN`（任意、DEPSCAN/DEPSOPS 共用の PAT。
  Contents: Read-only + Issues: Write + Pull requests: Write 推奨。未設定時は DEPSCAN/DEPSOPS
  のみエラー終了。Issues: Write が無い場合は Issue自動起票のみ失敗、Pull requests: Write が
  無い場合は DEPSOPS のPRマージ・rebase依頼コメントのみ失敗）

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
