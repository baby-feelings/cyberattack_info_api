---
name: crawler-internals
description: KEV/OSV/JVNクローラーおよびその共通基盤（app/core/配下のretry・notifications・db_utils・crawler_runner・pagination・schemas・stix・taxii、Alembicマイグレーション）の内部実装・設計判断を扱う。クローラーのバグ修正、新フィールド追加、STIX/TAXII配信の拡張、DBマイグレーション作成時に読む。
---

# クローラー内部実装リファレンス

`app/kev/` `app/osv/` `app/jvn/` および共通基盤 `app/core/` の設計判断集。

## 外部API呼び出しの耐障害性（Issue #130）
CISA KEVフィード・OSV API・MyJVN API・GitHub APIへの呼び出しは、`app.core.retry.
request_with_retry` で指数バックオフ付きリトライを行う。一時的な障害（429・5xx・
接続断）のみリトライ対象とし、恒久的なエラー（401/404、権限不足の403等）は即座に
呼び出し元へ伝播させる（無駄なリトライで失敗までの時間を延ばさないため）。GitHub
APIのレート制限は `X-RateLimit-Remaining`/`X-RateLimit-Reset`/`Retry-After` ヘッダーを
見て待機時間を決定する（`X-RateLimit-Reset` 経由の待機は最大5分でキャップし、
クロール全体が長時間ブロックされるのを防ぐ）。リトライ発生回数は
`external_api_retry_total`（Prometheus Counter、`reason` ラベルで
`rate_limited`/`transient_error` を区別）として `/metrics` に自動的に公開され、
Grafanaダッシュボードの「外部API呼び出しのリトライ発生回数」パネルで可視化する。

**新規リソース作成（POST）にはリトライを適用しない**: `create_issue`・
`add_issue_comment`・`request_rebase` は、タイムアウト等でレスポンス受信前に
失敗した場合、実際には成功しているリクエストを再送すると重複作成（Issue・
コメントの二重投稿等）のリスクがあるため、意図的にリトライ対象から除外している。
GET・PUT（`merge_pull_request`）・PATCH（`close_issue`）等の冪等な操作のみが
リトライ対象。

**Upsertロジックは冪等**: KEV/OSV/JVNの `_upsert_*` は自然キー（`cve_id`・
`(osv_id, ecosystem, package_name)`・`jvndb_id` 等）で既存レコードを検索し、
無ければINSERT・あれば内容差分がある場合のみUPDATEする設計のため、同じデータで
複数回実行しても結果は変わらない（重複INSERTは発生しない）。

**部分失敗時の再実行方針（設計判断）**: クロール処理の途中で例外が発生した場合、
現状は `crawler_logs` にエラーを記録し、クロール全体としては失敗扱いのまま
次回の定期実行（毎日）を待つのみで、即座の再試行は行わない。この方針を維持する
と判断した理由:
1. 個々のHTTPリクエストレベルの一時的障害は、上記のリトライ機構が既に吸収する
   （crawl全体の再実行が必要になるのは、外部APIが数分以上ダウンしている等、
   即座の再試行では解決しない障害であることが多い）
2. KEV/OSV/JVNは直近N日分（`OSV_DAYS`/`JVN_DAYS`等）を取得する設計のため、
   ある日のクロールが失敗しても、翌日以降のクロールが同じ期間を再度カバーし
   自然に「取りこぼし」を回収する
3. DEPSCAN/DEPSOPSは差分ではなく毎回全件を再評価する設計のため、失敗した回の
   状態は次回実行で完全に上書き・回復する
4. crawl全体の即時リトライを追加すると、DEPSCAN/DEPSOPSが内部で呼ぶ
   非冪等なGitHub API呼び出し（Issue作成等）が重複実行されるリスクが増す

## 通知関数の共通化（notifications.py）
`notify_success(crawler_type, inserted, updated, deleted)` と `notify_error(crawler_type, error)` の
2 つの汎用関数に統合。各クローラー（KEV/OSV/JVN/DEPSCAN/DEPSOPS/CODESCAN）はこれらを直接呼び出す
（`notify_new_vulnerabilities` 等のクローラー別ラッパーは廃止済み、DRY違反だったため削除）。
エラーメッセージは `_sanitize_error()` で接続文字列マスク + 200 文字制限。

**送信先の解決（Issue #227）**: 固定の`SLACK_WEBHOOK_URL`環境変数は廃止し、
`app.auth.account_store`（`UserAccount`テーブル、ダッシュボードから登録するSlack
Webhook）から動的に解決する。`notify_success`等の検知結果通知はKEV/OSV/JVNなら
通知有効な全登録ユーザーへブロードキャスト、DEPSCAN/DEPSOPS/CODESCANなら
`GITHUB_USERNAME`自身の登録Webhookにのみ送る。**`notify_error`だけは例外的に、
crawler_typeに関わらず常に管理者（`GITHUB_USERNAME`）自身の登録Webhookにのみ送る**
（`_resolve_admin_recipient`）。クローラー内部のエラーは運用担当者が対応すべき情報
であり、KEV/OSV/JVNのようなグローバル種別であっても無関係な一般ユーザーへ
ブロードキャストするとノイズ・情報漏洩になるため。

## DB ユーティリティの共通化（db_utils.py）
`year_month_expr(column)` は SQLite / PostgreSQL 両対応の YYYY-MM フォーマット式を返す共通関数。
3 つのルーター（vulnerabilities.py / osv.py / jvn.py）から共通利用する。

## クローラー実行の共通オーケストレーション（crawler_runner.py）
KEV/OSV/JVN の `fetch_and_store_*` が個別に持っていた「started_at計測 → DBセッション生成 →
本体処理 → crawler_logs記録 → Slack通知 → DBセッションクローズ」という定型処理を
`app.core.crawler_runner.run_crawler`（Template Method）に一元化している。各クローラーは
取得・Upsert・保持期間削除といったドメイン固有の処理のみを `body(db, counters)` 関数として
`run_crawler` に渡す。進捗件数は `CrawlCounters`（dataclass）で受け渡し、`body` が処理の進行に
応じて `counters.inserted`/`updated`/`deleted` を加算する。**エラー発生時もその時点までの
counters の値を crawler_logs に反映する**（OSV はエコシステム単位で処理を継続する既存挙動が
あり、途中で例外が発生してもそれまでに成功した件数を記録する。KEV/JVN はエラー時点で
件数がまだ確定していないため、従来通り 0/0/0 で記録される）。

**`_body`関数への注意**: KEV/OSV/JVNの`crawler.py`内の`_body`は`run_crawler(body=...)`に
クロージャとして渡すTemplate Methodのコールバックであり、直接の呼び出し元が見えない
（静的解析で「呼び出し元なし」と誤検知されやすい）。削除しないこと。

## /admin/*-crawl はバックグラウンド実行（202 即時返却）
`/admin/crawl`（KEV）・`/admin/osv-crawl`・`/admin/jvn-crawl`・`/admin/depscan-crawl`・
`/admin/codescan-crawl`・`/admin/dependabot-ops`・`/admin/repo-cleanup`（Issue #228）・
`/admin/user-crawl`（Issue #227）は即座に 202 Accepted を返し、
`app.core.background.run_in_background`（daemon スレッドで実行し、例外はログに記録するだけで
呼び出し元へは伝播させない共通ヘルパー）でバックグラウンド実行する。結果は
`/api/crawler-logs` で確認する（`repo-cleanup`は`crawler_type="CLEANUP"`で記録し、
`deleted`フィールドにパージしたリポジトリ数を格納する。`user-crawl`はユーザー単位の
処理のため`crawler_logs`には記録しない）。OSV・JVN は `?days=N` クエリパラメータで
取得対象日数を指定可能（初回バックフィル用）。

各エンドポイントは対応するドメインの `app/{kev,osv,jvn,depscan,depsops,codescan}/router.py`
に、`/api/xxx` prefix 付きの通常 `router` とは別に **prefix なし・`Security(require_api_key)`
で保護する `admin_router`** として定義する（`/api/vulnerabilities` 等の prefix に
`/admin/crawl` が巻き込まれてしまうのを避けるため）。`app/main.py` はこれらの router と
admin_router をすべて `include_router` するだけで、エンドポイント定義自体は持たない。

## ORM オブジェクトの datetime 自動変換（OrmDatetimeModel、core/schemas.py）
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

**新フィールド追加時は`model_fields`に含めるだけで自動対応する**ため、手動でdict組み立てを
書かないこと（同じ事故の再発防止）。

## 一覧APIのページネーション共通化（pagination.py）
`list_vulnerabilities`/`list_osv`/`list_jvn`/`list_depscan`/`list_depsops`/`list_codescan` がそれぞれ持っていた
「`query.count()` → offset算出 → `order_by`/`offset`/`limit` を適用して取得」という定型処理を
`app.core.pagination.paginate(query, page, per_page, order_by)` に一元化している。フィルタ条件
の構築（検索キーワード・重要度・エコシステム等の絞り込み）はドメインごとに大きく異なるため
対象外とし、真に共通していたページネーション部分のみを抽出した。

## SQLite / PostgreSQL 切り替え
`DATABASE_URL` が `sqlite://` で始まる場合は `check_same_thread=False` と PRAGMA 設定を自動適用。
PostgreSQL の場合は `pool_pre_ping=True` で接続断を自動検出。

## DBマイグレーションは Alembic で管理する
`app/main.py` の lifespan が呼ぶ `Base.metadata.create_all()` は新規テーブルの作成のみ行い、
既存テーブルへの列追加はしないため、本番 Neon DB のような**既に稼働中のDBへのスキーマ変更**は
create_all だけでは反映されない。カラム追加・変更を伴う機能は、モデル変更後に
`alembic revision --autogenerate -m "..."` でマイグレーションを生成し、`alembic/versions/`
配下にコミットすること（`.gitignore` から除外済み・Git管理下）。**新規NOT NULLカラムには
`server_default`を明示指定する**こと（autogenerateが生成する素のマイグレーションには
デフォルトが無く、既存Postgres行に対する適用で失敗する）。

`app/core/migrate.py` の `run_migrations()`（`python -m app.core.migrate` で実行）が
実際のマイグレーション適用を担う。**FastAPI の lifespan には組み込まない**
（`tests/conftest.py` が `Base.metadata.create_all` で直接テーブルを作る既存のテストDBに
対し、意図せず alembic の管理外操作が走ってテストが壊れるのを避けるため）。`Dockerfile`
の `CMD`（`python -m app.core.migrate && uvicorn ...`）として、アプリ起動前に明示的に
呼び出す運用とする。

**既存DB（alembic導入前）への一度きりの移行を自動化する自己修復ロジック**: `vulnerabilities`
テーブルは存在するが `alembic_version` テーブルが無い場合、現在のスキーマに一致する
ベースラインリビジョン（`_BASELINE_REVISION`）へ自動的に `stamp` してから `upgrade head`
する。真に空の新規DB（`vulnerabilities` テーブル自体が無い）の場合は stamp をスキップし、
先頭のリビジョンから全て適用する。

## KEV クローラーの EPSS スコア連携（Issue #127）
FIRST が提供する EPSS API（認証不要、`https://api.first.org/data/v1/epss`）から、
KEV に登録済みの全 CVE の悪用確率スコア・パーセンタイルを取得し `epss_score`/
`epss_percentile`/`epss_updated_at` に格納する。1リクエストあたり `_EPSS_BATCH_SIZE`
（100件）ずつカンマ区切りで問い合わせる。**毎回のKEVクロールで全件を再取得・上書き**する
（差分検知はしない。EPSSはCVE内容が変わらなくても日次で変動するモデル値のため）。
EPSS API 呼び出し失敗は他の保持期間削除処理と同様 try/except で握りつぶし、KEVクロール
自体の成功可否には影響させない。`GET /api/vulnerabilities` の `min_epss` パラメータで
絞り込み可能。

## 来歴・鮮度・差分API（Issue #129・KEV/OSV/JVN共通）
- **`fetched_at`**: クローラーが取得元で最後に存在確認した日時。既存の`updated_at`
  （内容が実際に変わった時だけ更新）とは異なり、**変更が無かった回のクロールでも毎回
  更新**する（鮮度の可視化用）。`changed`判定の等値比較には含めない
- **`updated_since`クエリパラメータ**: `fetched_at`は毎回更新されるため、内容が実際に
  変わった時だけ動く`updated_at`を条件に使う
- **OSVの`withdrawn_at`**: OSVスキーマの`withdrawn`フィールドをパースして保存
  （KEV・JVNには撤回の概念が無いため対象外）

SQLiteは`CURRENT_TIMESTAMP`が秒精度（マイクロ秒無し）のため、`updated_since`のテストで
同一秒内のinsertがcutoff比較に負けるレースコンディションに注意（`updated_at`を明示的な
固定値へ強制更新してから検証する。`test_*_updated_since_filter`参照）。

## KEV/OSV/JVNのSTIX 2.1 / TAXII 2.1配信（Issue #134）
当初はKEVのみ（`GET /api/vulnerabilities/{cve_id}?format=stix`）を実装し、その後OSV/JVNへ
拡張した。配信（読み取り専用）のみで、STIXオブジェクトのPUSH・TAXII固有の認証方式
（OAuth2等）はスコープ外。

- **`app/core/stix.py`**: KEV/OSV/JVN共通のSTIXヘルパー（`STIX_ID_NAMESPACE`・
  `stix_timestamp`）。`STIX_ID_NAMESPACE`の値は変更禁止（既存オブジェクトIDが変わる）
- **`app/kev/stix.py`**: オブジェクトIDは`uuid5(namespace, f"cisa-kev:{cve_id}")`。
  EPSSスコアは`x_epss_score`/`x_epss_percentile`というカスタムプロパティ（`x_`接頭辞）で付与
- **`app/osv/stix.py`**: OSVは`(osv_id, ecosystem, package_name)`の複合キーが自然キー
  のため、オブジェクトIDは`uuid5(namespace, f"osv:{osv_id}:{ecosystem}:{package_name}")`
  で生成する。`x_ecosystem`/`x_package_name`/`x_cvss_score`を付与
- **`app/jvn/stix.py`**: オブジェクトIDは`uuid5(namespace, f"jvn:{jvndb_id}")`。
  `x_cvss_score`/`x_cvss_vector`を付与
- **`GET /api/vulnerabilities/{cve_id}?format=stix` / `GET /api/jvn/{jvndb_id}?format=stix`**:
  戻り値の型を`XxxOut | Response`とし、`format=stix`時は`Response`を直接返すことで
  FastAPIの自動シリアライズをバイパスする。**`response_model=None`の明示指定も必要**
  （型アノテーションのUnionだけでは`FastAPIError: Invalid args for response field`になる）
- **`GET /api/osv/{osv_id}?format=json|stix`**: OSVは`osv_id`だけでは一意でないため、
  該当`osv_id`の全行を**リスト**（json）または**STIX Bundle**（stix）で返す（KEV/JVNの
  「単一オブジェクトを返す」設計とは意図的に異なる）
- **`app/core/taxii.py`**: `/taxii2/`配下、`require_public_api_key`で保護。
  コレクションレジストリパターン（コレクションID・クエリ関数・単体取得関数を紐づける
  マッピング）で複数ドメインに対応。単一API root・複数コレクション構成。manifest
  エンドポイント・フルのTAXIIページネーションは省略した簡易実装
- **コレクションID（固定値、変更禁止）**: KEV=`d4d8f0c0-3f5f-5b1e-9c1a-6f6f6a6b6a6a`・
  OSV=`84be1117-7e69-58ed-a0dc-d2f2bb7f60ca`・JVN=`1c34f413-fd30-56cc-bf87-daf79113b5a8`
- **object単体取得の制約**: STIXオブジェクトIDは自然キーの一方向ハッシュ（uuid5）のため、
  `GET .../objects/{object_id}/`は全レコードに対して再計算・照合する線形走査になる。
  各カタログの規模（数千件程度）では実用上問題ないが、大規模拡張時は`stix_id`列を追加し
  インデックス検索に切り替える必要がある

## OSV クローラーの 2 ステップ取得
OSV REST API の `/v1/querybatch` は `{id, modified}` しか返さないため、完全情報の取得は 2 ステップ:
1. `POST /v1/querybatch` → 脆弱性 ID と最終更新日時の一覧を取得
2. cutoff（`OSV_DAYS` 日前）より新しいものだけ `GET /v1/vulns/{id}` で完全情報を取得

対象エコシステムは `app/osv/packages.py` の `POPULAR_PACKAGES`（PyPI / npm / Go / Maven /
RubyGems / NuGet / crates.io / Packagist / Hex / Pub）。

**DB保護**: Neon無料プランは長時間トランザクションがタイムアウトする → `_COMMIT_EVERY = 50`
件ごとに定期コミット。`(osv_id, ecosystem, package_name)` の複合ユニーク制約あり →
Upsert前にリスト内の重複を除去。`OSV_RETENTION_DAYS`（既定180日）超過レコードは自動削除。

## JVN クローラーの XML パース
MyJVN API（`https://jvndb.jvn.jp/myjvn`）は RDF/RSS 1.0 形式で返す。XML 名前空間に注意:
- JVNDB ID: `<sec:identifier>` 要素（`dc:identifier` ではない）
- 影響製品: `<sec:cpe vendor="..." product="...">` 要素（`sec:affected` ではない）
- CVE 参照: `<sec:references source="CVE" ...>` の `source` 属性（`type` 属性ではない）
- `<title>` / `<link>` は RSS 既定名前空間（`rss:`）に属するため `rss:title` / `rss:link` で検索
- defusedxml を使用して XXE / Billion-laughs 攻撃を防止

## pytest フィクスチャ構成
- `setup_test_db`（`scope="session"`）: テスト DB のテーブル作成・削除
- `clean_db`（`autouse=True`）: 各テスト後に全レコード削除
- `client`: `dependency_overrides` でテスト DB を注入した `TestClient`
- `db_session`: テスト用 SQLAlchemy セッション

**Windows でのテスト DB ファイルロック**: teardown時は `test_engine.dispose()` で
コネクションを解放してから `os.remove("test.db")` する（`OSError` は無視）。dispose せず
削除すると Windows ではファイルロックで失敗する。
