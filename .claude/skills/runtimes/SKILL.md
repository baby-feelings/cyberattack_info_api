---
name: runtimes
description: 言語・実行環境のバージョン監視（RUNTIME。Issue #373）の内部設計。設定ファイルからの使用版の検出（Dockerfile・CI・firebase.json 等）・最新版とサポート期限の取得元（endoflife.date・Flutter公式）・状態の判定（eol/eol_soon/update_available）・閲覧API・毎日の実行を扱う。app/runtimes/配下の変更、検出する設定ファイルや言語の追加時に読む。
---

# RUNTIME 内部実装リファレンス

## 何をするか
各リポジトリが使っている言語・実行環境（Python / Node.js / Flutter / Dart）の版を、設定ファイルから
検出し、最新版・サポート期限（EOL）と突き合わせる。サポートが切れた版や、新しい版が出たことに早く
気づくため（Issue #373）。DEPSCAN と同じく、`GITHUB_USERNAME` 配下の全対象リポジトリ
（`list_target_repos`。fork・archived・`SCAN_EXCLUDE_REPOS` は除外）を、毎日スキャンする。

## 構成（`app/runtimes/`）
| ファイル | 役割 |
|---|---|
| `detector.py` | ファイルのパスと内容 → 使っている言語・実行環境（純粋な変換。HTTP・DB に触れない） |
| `eol_client.py` | 最新版・サポート期限の取得（endoflife.date と Flutter 公式の `releases_linux.json`） |
| `status.py` | 使っている版の状態の判定（純粋。日付は引数） |
| `repository.py` | 永続化（`runtime_releases` の upsert、`repo_runtimes` のリポジトリ単位の全置換） |
| `crawler.py` | 毎日のジョブ（`CrawlJob`。種別 `RUNTIME`。成功を Slack へ流さず、変化があったときだけ`alerts`で通知） |
| `alerts.py` | 通知の判定（新しい系列の公開・サポート終了が近い・サポート終了）と、送信済みの記録（`runtime_alerts`） |
| `filters.py` | 絞り込み条件の値オブジェクト`RuntimeFilter`（`for_owner`・`apply`。`depscan/inventory/filters.py`と同じ設計） |
| `browse.py` | 閲覧用の絞り込み・集計（状態は保存せず、閲覧のたびに求める） |
| `router.py` / `schemas.py` | `GET /api/runtimes`・`/repos`・`/releases`、`POST /admin/runtime-crawl` |

テーブルは2つ（Alembic `b8d4f2a61c93`）。`runtime_releases`（言語×系列ごとの最新版・EOL・LTS）と
`repo_runtimes`（リポジトリが使っている版・由来のファイル・`pinned`）。

## 検出する場所（`detector.py`）
| ファイル | 検出 | `pinned` |
|---|---|---|
| `Dockerfile*` の `FROM python:3.13` / `node:24` | Python・Node.js | True |
| `.python-version` `.nvmrc` `.node-version` `.tool-versions` `.fvmrc` | 各言語 | True |
| `.github/workflows/*.yml` の `python-version` `node-version` `flutter-version` | 各言語 | True |
| `firebase.json` の `runtime`（`python313` → 3.13、`nodejs24` → 24） | Python・Node.js | True |
| `package.json` の `engines.node` | Node.js | False（下限） |
| `pubspec.yaml` の `environment.sdk` / `flutter` | Dart・Flutter | False（下限） |
| `pyproject.toml` の `requires-python` | Python | False（下限） |

- **`pinned=False`（下限の指定）は、状態を `reference` にして、警告・通知の対象にしない**。`>=22` は
  実際に動いている版ではないため、期限切れ・更新ありと判定すると誤警告になる
- 版は「系列」にそろえる（`to_cycle`）。Node.js はメジャーのみ（`24`）、Python・Flutter・Dart は
  メジャー.マイナー（`3.13`）。マイナーが分からないもの（`python:3-slim`、`3.x`）・
  `${{ matrix.x }}`・`lts/*` は読み取れないため検出しない
- 外部のリポジトリのファイルを読むため、**正規表現は入れ子の量指定子を避け、1行ずつ・長さを切って
  処理する**（ReDoS 対策。`tests/runtimes/test_detector.py::TestRobustness` が検査）
- 1リポジトリあたり取得する設定ファイルは 40 件・1 ファイル 300KB まで。`node_modules` 等は除外
- ファイルツリーを取得できなかったリポジトリは、保存せず、前回の内容を残す（空で上書きしない）

## 最新版・サポート期限の取得元（`eol_client.py`）
- **Python・Node.js**: `https://endoflife.date/api/v1/products/{python,nodejs}/`
  （`name`=系列、`latest.name`、`eolFrom`、`isEol`、`isLts`）
- **Flutter・Dart**: endoflife.date に載っていないため、Flutter 公式の
  `releases_linux.json`（stable のみ）から系列ごとの最新版を求める。Dart の版は、各 Flutter リリースに
  同梱の `dart_sdk_version`。サポート期限は定められていない（`eol_date=NULL`）。1.x・2.x は保存しない
- 取得元ごとに失敗を切り分け、一部が失敗しても取れた分は保存する。**全て失敗したときだけクロール失敗**
  （crawler_logs に error・Slack にエラー通知）
- 取得元から消えた系列は DB から消さない（EOL を過ぎて一覧から外れた古い版を使うリポジトリの判定に必要）

## 状態の判定（`status.py`）
| 状態 | 条件 |
|---|---|
| `eol` | サポート終了（`is_eol`、または `eol_date` が過去） |
| `eol_soon` | サポート終了まで `EOL_SOON_DAYS`（180）日以内 |
| `update_available` | 推奨の系列が、使っている系列より新しい |
| `latest` | 推奨の系列を使っている |
| `reference` | `pinned=False`（下限の指定）。参考表示のみ |
| `unknown` | リリース情報に無い系列（取得前など） |

- **推奨の系列**: サポート中で、**公開から 180 日（`RECOMMEND_MIN_AGE_DAYS`）以上経った**最新。
  公開直後の系列は、ライブラリの対応が追いつかず、使っているリポジトリが全て「更新あり」に
  なって警告が多くなるため。経った系列が無ければ、サポート中の最新。公開日が不明（NULL）なものは
  経ったものとして扱う。**Node.js は LTS のみ**（偶数の系列。奇数の系列は短命のため）
- Flutter・Dart の公開日は、系列の**最初**のリリースの日（最新のパッチの日にすると、パッチが
  出るたびに「公開直後」に戻ってしまう）
- `eol`・`eol_soon`・`update_available` が「対応が必要」（`NEEDS_ACTION_STATES`）。`needs_action=true` の
  絞り込みと、リポジトリ別の件数（`/repos`）の対象
- 状態は DB に保存しない（期限が日々近づくため、保存すると古くなる）。件数が少ない（リポジトリ数×数件）
  ため、条件に合う行を全て取って Python で判定し、絞り込む（DB のページネーションは使わない）

## Slack 通知（`alerts.py`・`core/notifications/runtime_alerts.py`）
毎日の実行の成功後に、**変化があったときだけ**、管理者（`GITHUB_USERNAME`）の Slack に送る。毎日同じ内容を
送ると見なくなるため。3種類（言語・系列ごと。キーは`<種類>:<言語>:<系列>`、例`eol_soon:python:3.11`）:

| 種類 | 条件 |
|---|---|
| `new_release` | 新しい系列が公開された（公開から`NEW_RELEASE_WINDOW_DAYS`=90日以内。その言語を使う運用中のアプリがあるときだけ） |
| `eol_soon` | 使っている系列のサポート終了が`EOL_SOON_DAYS`=180日以内（運用中のアプリが**版を固定**して使うものだけ） |
| `eol` | 使っている系列のサポートが終了した（同上） |

- **送った通知は`runtime_alerts`に記録**し、同じキーは二度と送らない。**送信に失敗したものは記録せず**、
  翌日の実行でもう一度送る
- **最初の実行は、既存の状況を記録するだけで通知しない**（`initialized`の印を残す。導入した日に、
  これまでの全系列の通知が一度に届かないため）
- 通知の失敗でクロールを失敗にしない（`after_success`で`try/except`）。coreは`RuntimeAlertItem`を知らず、
  辞書（`as_dict()`）を受け取る
- 下限の指定（`pinned=False`）・運用停止中のアプリは、通知の対象にしない

## API とアクセス制御
DEPSCAN と同じく `X-API-KEY` または GitHub ログインのセッションが必要（`require_api_key_or_session`）。
**セッション認証時は本人所有のリポジトリのみに強制的に絞る**（`startswith` による前方一致。LIKE だと
`a_b` が `aXb` に一致するため）。`/releases` はリポジトリ情報を含まないため絞り込まない。
`operating=active|inactive|all` は DEPSCAN と共通（`INACTIVE_REPOS`）。

## 実行時刻
`RUNTIME_CRON_HOUR_UTC` / `RUNTIME_CRON_MINUTE_UTC`（既定 UTC 22:45。CODESCAN の後段・DEPSOPS の前）。
強制実行は `POST /admin/runtime-crawl?force=true`、結果は `/api/crawler-logs?crawler_type=RUNTIME`。

## 削除済みリポジトリの掃除
`jobs/repo_cleanup` が、削除済みリポジトリの `repo_runtimes` と DEPSCAN の `repo_dependencies`
（SBOM の全量）も消す。**新しいリポジトリ単位のテーブルを足したら、`_find_known_repos` と
`_purge_repo_data` に足すこと**（足し忘れると、削除済みリポジトリの行が残り続ける）。

## 言語・設定ファイルを足すとき
1. `detector.py` に検出関数を足し、`_BY_BASENAME`（ファイル名）か `is_candidate` に登録する
2. 新しい言語なら、`RUNTIMES`・`RUNTIME_LABELS` に足し、`eol_client.py` に取得元を足す
3. `tests/runtimes/` に、検出・読み取れない入力・長い入力（ReDoS）のテストを足す
