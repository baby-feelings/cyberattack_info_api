---
name: depscan-depsops
description: DEPSCAN（GitHub全リポジトリの依存ライブラリ脆弱性スキャン）とDEPSOPS（Dependabot PR自動運用）の内部設計。到達可能性判定・資産コンテキスト・優先度推薦・SBOMエクスポート・GitHub Issue自動起票/クローズ・DEPSOPSの自動マージ判定ロジック・GitHub OAuthログイン・ユーザー別Slack通知登録（UserAccount、Issue #227）と登録済みユーザー向け定期実行を扱う。app/depscan/・app/depsops/・app/auth/・app/core/user_crawl_runner.py配下の変更時に読む。
---

# DEPSCAN / DEPSOPS 内部実装リファレンス

## DEPSCAN はリアルタイムで OSV API に照合する（事前クロール済みデータには頼らない）
既存の `OsvVulnerability` テーブルは `POPULAR_PACKAGES`（各エコシステム50〜60件の主要パッケージ）しか
収録していないため、GitHub 上の自作アプリが依存する任意のパッケージを検知するには不十分。
そのため DEPSCAN は `app.core.osv_client.query_versions_batch` で **バージョン指定の OSV API を
その場でクエリ**し、既存 DB とは独立して脆弱性を判定する。GitHub リポジトリの列挙は
`GITHUB_USERNAME`（fork・archived は自動除外）、認証は `GITHUB_TOKEN`（fine-grained PAT,
Contents: Read-only + **Issues: Write** 推奨）を使用する。

`list_target_repos` は `GET /user/repos`（`affiliation=owner`）を使う（`GET /users/{username}/repos`
は公開リポジトリのみ返す仕様のため、プライベートリポジトリを含めるにはこちらが必須。PR #72で修正）。

ロックファイル検出は `app.depscan.github_client.get_repo_tree` で `git/trees/{branch}?recursive=1`
を使い、サブディレクトリ（monorepo）も含めて全ファイルパスを1回のAPI呼び出しで取得する。
対応する10エコシステムのロックファイル名は `app.depscan.parsers.LOCKFILE_FILENAMES` で判定する。

## DEPSCAN の新規検知は GitHub Issue としても自動起票する（issue_management.py）
`app.depscan.issue_management._file_github_issues` が、新規検知を検知されたリポジトリ自身に
Issue として起票する（Slack通知と同じ `new_snapshots` を使用）。タイトル固定文字列で
Open Issue を検索し、あれば `add_issue_comment` で追記、無ければ `create_issue` で新規作成する
（1リポジトリにつき常に1つの Open Issue に集約するため）。本文の整形ロジック
（`format_package_lines`）は Slack 通知（`app.core.notifications`）と共有するため
`app.core.finding_format` に切り出してある。GitHub API 呼び出し失敗（`Issues: Write` 権限
不足等）はリポジトリ単位で `except httpx.HTTPError` により握りつぶし、DEPSCAN 全体の
成功可否には影響させない。

`_close_resolved_repo_issues` が、DEPSCAN の再スキャンで「そのリポジトリの未解決 finding が
実際に0件になったこと」を確認できたタイミングで Open な DEPSCAN Issue を自動的にクローズする。
トリガーを **DEPSCAN の再スキャン検証後**とし、DEPSOPS の PR マージ直後に即座にクローズしない
設計（マージしただけでは本当に脆弱性が解消されたか未検証のため）。`_resolve_stale_findings`
が返す `affected_repos`（今回1件以上解決したリポジトリの集合）を候補として受け取り、そのリポジトリ
に絞って再度 DB に問い合わせてから判定する（無関係なリポジトリへの無駄な GitHub API 呼び出しを
避けるため）。クローズ前に `add_issue_comment` で解決報告コメントを追加してから `close_issue`
（PATCH `state=closed`）を呼ぶ。

## DEPSCAN の到達可能性（reachability）ヒューリスティック判定
「脆弱な依存が存在すること」と「実際に到達・悪用可能であること」は別問題（依存スキャナの
偽陽性の主因は到達不能コードの検知）。`app.depscan.reachability`が、脆弱なパッケージが
リポジトリのソースコード内で実際に**import/require/useされているか**（importレベルのみ。
関数呼び出しレベルの解析はスコープ外）を判定し、`DependencyFinding.reachability`
（`"reachable"`/`"unreachable"`/`"unknown"`）へ格納する。対応は全10エコシステム。
パッケージ名からソース内識別子への変換精度はエコシステムにより差が大きく、Maven・
Packagist・Hexは最も精度が低いbest-effort。`get_source_files`が対象リポジトリの
ソースを取得（`_MAX_SOURCE_FILES=200`件・`_MAX_SOURCE_FILE_SIZE=300_000`バイト上限）し、
`_apply_reachability`がリポジトリ×エコシステムごとに1回だけ使い回す。取得失敗は
`"unknown"`のまま残す。再スキャンのたびに既存レコードの`reachability`も再計算・上書きする。

## DEPSCAN の資産コンテキスト（Issue #131：多層リスク優先度づけ）
「脆弱性そのものの深刻度」＋「実際にどの資産に影響するか」＋「その資産がインターネットに
露出しているか」を組み合わせてこそ、対応の優先度を正しく判断できる（SSVC的な意思決定支援）。

- **`DependencyFinding.repo_visibility`**（`"public"`/`"private"`）: GitHub APIの
  `private`フィールドから`_collect_dependencies`が自動導出し、スキャンのたびに上書き
  （手動設定不要）
- **`RepoAssetContext`テーブル**（`app/depscan/models.py`）: `is_production`・
  `is_internet_facing`・`importance`（`"high"`/`"medium"`/`"low"`）を管理者が
  `PUT /admin/depscan/assets/{owner}/{repo}`で手動設定（Upsert）。低頻度更新のため
  DB＋管理API方式を採用し、静的設定ファイル方式（変更にデプロイが必要）は見送った
- `GET /api/depscan`のレスポンスには`repo_visibility`（フラット）・`asset_context`
  （ネスト、未設定なら`null`）として埋め込む。`app.depscan.priority._fetch_asset_context_map`
  が一覧取得のたびに該当リポジトリ群をまとめて1回で問い合わせる（N+1回避）
- `GET /api/depscan/assets`で設定済みの資産コンテキストを一覧取得できる（未設定は含まれない）

## DEPSCAN の説明可能な優先度推薦（Issue #135：priority_reasons、app/depscan/priority.py）
#131・#127（EPSS）・#132（到達可能性）の実装完了を前提に、「なぜその脆弱性の優先度が
高いと判断されたか」を機械可読な理由コード配列として提示する。

- `DependencyFinding.cve_ids`（JSON配列）: OSVエントリの`aliases`から`CVE-`始まりの
  IDのみ抽出して保存する（`_build_findings`が設定）。OSV ID単独ではKEVテーブルの
  `cve_id`と直接対応しないため、突合用に別途保持する
- `GET /api/depscan`のレスポンスの`priority_reasons`は`app.depscan.priority
  ._compute_priority_reasons`が判定する（複数該当可）:
  - `kev_listed`: `cve_ids`のいずれかがCISA KEVに掲載されている
  - `epss_high`: KEV側マッチレコードの`epss_score`が`_EPSS_HIGH_THRESHOLD`（0.5）以上
  - `reachable` / `public_repo` / `internet_facing_asset` / `production_asset` /
    `high_importance_asset`: それぞれ`reachability`/`repo_visibility`/`asset_context`
    から導出
  - KEV突合は`_fetch_kev_map`が一覧取得のたびに該当CVE群をまとめて1回で問い合わせる
- **書き込み時ではなく読み取り時に計算する**設計（KEV掲載・EPSSスコアはDEPSCANの
  スキャンとは独立して毎日更新されるため、再スキャンなしで常に最新状態を反映できる）
- ダッシュボード（`DepscanGroupRow.tsx`）では、いずれかのCVEが`kev_listed`の場合に
  赤い「KEV」バッジを行レベルで表示し、それ以外は展開時のCVE単位の内訳でバッジ表示する

## DEPSCAN のSBOMエクスポート（Issue #133：CycloneDX/SPDX、app/depscan/sbom.py）
OWASP Top 10:2025「ソフトウェアサプライチェーンの失敗」対策。**対応範囲はエクスポート
（読み取り専用）のみ**で、外部SBOMの入力受け付け・VEX拡張はスコープ外。

- **`build_purl`**: パッケージ情報からpurlをbest-effortで組み立てる。Maven
  （`groupId:artifactId`）・Packagist（`vendor/name`）・npm（`@scope/name`）は
  namespace/nameに分解、それ以外はパッケージ名をそのまま`name`として扱う
- **`GET /api/depscan/export`**: `repo`（必須）・`format`（`cyclonedx`/`spdx`）・
  `resolved`で絞り込み。認証は`GET /api/depscan`と同じ`_resolve_access`
- **CycloneDX**: `components`は`(ecosystem, package_name, installed_version)`単位で
  重複排除、`vulnerabilities`は元のfindingごとに1件。1パッケージに複数CVEが紐づく場合、
  componentは1つにまとまり`vulnerabilities`だけ複数件になる
- **SPDX**: コア仕様（2.3）には脆弱性を表現する概念が無いため、`packages`のみを返す
- レスポンスの`Content-Type`は`application/vnd.cyclonedx+json`・`application/spdx+json`

## DEPSCAN の解決済みレコードは保持期間超過で自動削除する（未解決は対象外）
`app.depscan.crawler._delete_old_depscan_records` が、`resolved_at` が
`DEPSCAN_RETENTION_DAYS`（既定180日）より古いレコードのみを削除する。**未解決のレコードは
経過期間に関わらず削除しない**（対応が必要な情報のため履歴として残す）。

`CrawlerLog`（`crawler_type="DEPSCAN"`）の意味: `inserted`=新規検知件数、`deleted`=今回の
スキャンで解決済みにした件数（削除ではない）、`updated`=保持期間超過の**実削除**件数
（DEPSCANの`updated`は元々常に0だったため、新カラムを追加せずここへ格納している）。

## DEPSOPS（app/depsops/）: Dependabot PR の安全な自動マージ運用層
DEPSCAN（検知）・Dependabot（修正PR作成）に続く3層目として、**安全性が高いPRだけを
自動マージする**運用層。`POST /admin/dependabot-ops`から`run_dependabot_ops`を呼ぶ
（`DEPSOPS_CRON_HOUR_UTC`＝既定UTC 23:00=JST 8:00、DEPSCANの後段で自動実行）。
`run_dependabot_ops`本体はオーケストレーションのみに専念し、リポジトリ単位の判定・
マージは`_process_repo`、対象リポジトリ走査は`_scan_target_repos`に分解している。
コンフリクトでマージできなかったPRは、翌日以降リベースが完了していれば自動的に
再判定・マージされる（複数日にまたがる自己修復）。

**判定ロジック**（`_process_pr`、上から順に評価）:
1. `mergeable_state == "dirty"`（コンフリクト）→ `@dependabot rebase`をコメントしflagged
2. 対象リポジトリにCI（`.github/workflows`）が無い → 常にflagged
3. `classify_bump`の判定が`"major"`または`"unknown"` → flagged。**0.x系はminorの変化も
   major扱い**（semverの慣習）
4. `mergeable_state != "clean"`（CI失敗・レビュー待ち等）→ flagged
5. いずれにも該当しない（マイナー/パッチ・CIあり・コンフリクトなし）→ 自動マージ

マージ・flaggedいずれも毎回Slack通知（0件同士のみスキップ）。判定結果は
`DependabotPrLog`テーブルへ1PR1行で永続化し、`GET /api/depsops`で参照する。
ダッシュボードにはDEPSOPS専用タブは作らず、DEPSCANタブ内のボタンから開く
全画面モーダル（`DependabotOpsModal.tsx`）として統合している。

**`is_security_update`**: `list_open_dependabot_alerts`でリポジトリのOpenなDependabot
alert対象パッケージ名を取得し、PRタイトルと単語境界一致で照合する。`GITHUB_TOKEN`に
Dependabot alertsの読み取り権限が必要（classic PAT: `security_events` / fine-grained
PAT: 「Dependabot alerts: Read-only」）。無い場合は`null`のまま記録され、**過去の記録は
遡って再判定されない**。

**`compatibility_badge_url`**: DependabotがPR本文に埋め込む「Compatibility score」
バッジ画像URLを正規表現で抽出し保存する（GitHub側に数値取得APIが無いため）。

**`action="closed"`**: `flagged`記録したPRが、Dependabotの自動クローズや人手による
マージ等DEPSOPSの関知しないところで解消されても記録する手段が無く、ダッシュボードの
「未解決」件数が実態と乖離する不具合があった（parent_diaryリポジトリで発覚）。
`_find_resolved_flagged_prs`が、直近`flagged`記録されたPRのうち今回のOpen PR一覧に
含まれなくなったものを`action="closed"`として記録する。`CrawlerLog`
（`crawler_type="DEPSOPS"`）の`deleted`フィールドはこの`closed`記録件数を表す。

## Dependabot の有効化（本リポジトリ + DEPSCAN対象の全リポジトリ）
GitHub の Dependabot には独立した2つの機能があり、**`dependabot.yml` を置くだけでは
「Dependabot version updates」しか有効にならない**。DEPSCANが検知したような脆弱性に
即座に修正PRを出す「Dependabot security updates」は、各リポジトリの
`Settings → Code security` で個別にON（`Dependency graph`・`Dependabot alerts`・
`Dependabot security updates`）にする必要がある。
**Dependabot PR は内容を確認せず自動マージしないこと。** メジャーバージョンアップは
非互換な依存衝突を起こしうる（実例: `typescript` 6.0.3→7.0.2が`typescript-eslint`の
peer依存と衝突しVercelビルドが失敗）。マージ前にCIに加え、フロントエンド変更は
Vercelプレビューデプロイの完了を確認する。

**マージ時のチェックリスト**:
1. `mergeable: MERGEABLE`を確認（`gh pr view <num> --json mergeable`）
2. メジャーバージョンアップはマージ後のデプロイ結果を確認してから次に進む
3. 連続マージで`package-lock.json`等の競合が起きたら`@dependabot rebase`とコメント
4. リベース後、別PRのマージで既に修正済みバージョンに達していた場合Dependabotが
   PRを自動クローズすることがある（異常ではない）
5. **本番反映方法はリポジトリごとに異なる**（Vercel連携ありはマージ時自動、
   `todo-app`〈Firebase Hosting〉はマージ後に手動`firebase deploy`が必要）

**新規リポジトリ作成時のチェックリスト**（`baby-feelings`は個人アカウントのため
Organization全体への一括デフォルト設定が無い）:
1. `.github/dependabot.yml`を追加（対応エコシステムは`app.depscan.parsers.LOCKFILE_FILENAMES`参照）
2. `Dependabot alerts`・`Dependabot security updates`を有効化:
   ```bash
   gh api -X PUT repos/baby-feelings/<repo>/vulnerability-alerts
   gh api -X PUT repos/baby-feelings/<repo>/automated-security-fixes
   ```

## GITHUB_USERNAME は必須環境変数（デフォルト値なし）
`GITHUB_TOKEN`（未設定でもアプリは起動しDEPSCANだけがエラー終了）とは異なり、
`GITHUB_USERNAME` は `Settings` でデフォルト値を持たない必須項目。未設定だと
`Settings()` のインスタンス化（アプリ起動時）に失敗し、**アプリ全体が起動できない**。
ローカル開発・CI 双方で明示的に設定する必要がある（`tests/conftest.py` の
`os.environ.setdefault` と `.github/workflows/ci.yml` の `env:` を参照）。

## DEPSCAN ダッシュボードの GitHub ログイン・アクセス制御（Issue #107、app/auth/）
任意の GitHub アカウントで OAuth ログインし、**本人が所有するリポジトリの検知結果のみ**
表示する（UIゲートではなくバックエンド側で強制するアクセス制御）。

- **OAuthフロー**: `/auth/github/login` → GitHub認可（scope `repo`）→
  `/auth/github/callback` で `code` を `access_token` に交換しログインユーザー名取得 →
  セッションJWT（PyJWT、`SESSION_SECRET_KEY`でHS256署名、24時間有効）発行
- **セッションJWTの受け渡しは使い捨て交換コード方式**: JWT本体をURLクエリに載せるのは
  RFC 9700違反、Cookie方式はSafari ITPがクロスサイトCookieをブロックしiOS PWAでログイン
  できない不具合が実際に発生した（過去2回の設計変更を経て現方式に到達）。現在は
  `/auth/github/callback` が数十秒だけ有効な使い捨て交換コードを`?depscan_code=...`で
  フロントエンドへ渡し、フロントエンドが即座に`POST /auth/exchange`でセッションJWTと
  交換、以降`Authorization: Bearer <token>`を`localStorage`経由で使う
- **`/api/depscan`系の認証**: `_resolve_access`（`app.depscan.router`）が
  `X-API-KEY`（フルアクセス）または `Authorization: Bearer <セッションJWT>` を検証。
  セッション認証時は`owner`を強制的にログインユーザー名で上書きし、`repo`パラメータで
  他人のリポジトリを直接指定しても403。**検証ロジック自体（`hmac.compare_digest`での
  APIキー比較、`decode_session_token`でのBearerトークン検証）は
  `app.core.auth.require_api_key_or_session`に共通化されている**（Issue #219。CODESCAN
  もGitHubログインを必須にする際、DEPSCAN固有の「オーナー絞り込み」とコアの検証ロジック
  を分離する必要があったため切り出した。DRY原則）。`_resolve_access = 
  require_api_key_or_session` という単純なエイリアスで、DEPSCANの外部から見える
  振る舞い・レスポンス形式は一切変えていない。CODESCAN（`app.codescan.router`）は
  同じ共通関数を使うが、戻り値を絞り込みには使わず「ログイン済みかどうか」のみを
  ゲートとして使う（詳細は`.claude/skills/codescan/SKILL.md`）
- **オンデマンドスキャン**（`run_depscan_for_user`）: 毎日クロールは`GITHUB_USERNAME`
  専用のため、任意アカウントはログイン時にその場でスキャンする。`crawler_logs`記録は
  行わない。進捗は`UserScan`テーブルに記録し`/auth/scan-status`でポーリング取得。
  直近24時間以内に完了済みなら再スキャンをスキップ。Slack通知・GitHub Issue起票は、
  本人がSlack Webhookを登録して通知を有効にしている場合のみ行う（Issue #227、詳細は
  下記セクション）。未登録のまま単にログインしただけでは一切通知・起票しない
- **`_resolve_stale_findings`のクロスユーザー事故防止**: `repo_owner_prefix`引数で
  そのユーザーのリポジトリのみに絞り込む（無絞り込みだと他ユーザーのfindingを誤って
  解決済み扱いにする）
- **フロントエンド**（`DepscanAuthGate.tsx`）: ネットワーク瞬断等の一時的エラーでは
  ログアウトさせず、セッションが実際に無効（401）な場合のみログアウト扱いにする
  （`UnauthorizedError`で区別）

## ユーザー別Slack通知登録とDEPSCAN/CODESCAN/DEPSOPSの定期実行（Issue #227、app/auth/、app/core/user_crawl_runner.py）
DEPSCANのGitHubログインを土台に、任意のユーザーが自分専用のSlack Webhookを登録し、
自分自身のリポジトリに対するDEPSCAN/CODESCAN/DEPSOPSの検知結果を受け取れる機能。

- **`UserAccount`テーブル**（`app.auth.models`）: `github_username`を主キーに、
  `github_access_token_encrypted`（Fernet暗号化、`app.core.crypto`。
  `TOKEN_ENCRYPTION_KEY`未設定時は暗号化に失敗しトークン保存自体をスキップする
  ソフトフェイル方針）・`slack_webhook_url`・`notifications_enabled`を持つ。
  **ログインのたびに**`upsert_user_token`（`app.auth.account_store`）でトークンを
  最新化する（従来はログイン直後のオンデマンドスキャン1回にしか使わず保存して
  いなかったが、登録済みユーザー向けの定期実行に使うため永続化するよう変更した）
- **`GET/PUT/DELETE /auth/notification-settings`**: Webhook登録・解除API。
  `PUT`は`send_test_notification`で実際にテスト送信し、成功した場合のみDBへ保存する
  （不正なURLを誤登録する事故を防ぐ）。バリデーションは`https://hooks.slack.com/`
  プレフィックスの簡易チェックのみ（本物かどうかはテスト送信の成否で判断する）
- **通知先の解決**（`app.core.notifications._resolve_recipients`）: `SLACK_WEBHOOK_URL`
  環境変数は廃止し、`UserAccount`から動的解決する方式に移行した。KEV/OSV/JVN
  （リポジトリに紐づかないグローバルな脅威情報）は通知有効な全登録ユーザーへ
  ブロードキャスト、DEPSCAN/DEPSOPS/CODESCANの`GITHUB_USERNAME`向け毎日クロールは
  `GITHUB_USERNAME`自身の登録Webhookにのみ送る。**`notify_error`だけは例外**で、
  crawler_typeに関わらず常に管理者（`GITHUB_USERNAME`）自身のWebhookにのみ送る
  （`_resolve_admin_recipient`。クローラー内部エラーは運用担当者向けの情報であり、
  グローバル種別でも全登録ユーザーへ通知するとノイズ・情報漏洩になるため）
- **`app.core.user_crawl_runner.run_user_crawls_for_all_accounts`**:
  `GITHUB_USERNAME`以外で、かつSlack Webhookを登録・有効化しているユーザーのみを
  対象に、本人のトークンでDEPSCAN→CODESCAN→DEPSOPSを順に実行し、削除済みリポジトリの
  掃除（`app.core.repo_cleanup`）も行う。Webhook未登録者は対象外とする設計（通知先が
  無いままDEPSOPSの自動マージのようなリポジトリ変更操作を行うのは想定外の驚きになる
  ため、Webhook登録をopt-inのゲートとして使う）。`USER_CRAWL_CRON_HOUR_UTC`/
  `MINUTE_UTC`で毎日実行、`POST /admin/user-crawl`で手動実行も可能
- **Issue起票・PRマージの権限分離**: `app.depscan.issue_management._file_github_issues`・
  `app.codescan.issue_management._file_github_issues`・`app.depsops.runner._process_repo`
  にいずれも`token`引数（省略時`settings.GITHUB_TOKEN`）を追加した。`GITHUB_TOKEN`
  （baby-feelings専用PAT）には他ユーザーのプライベートリポジトリへの書き込み権限が
  無いため、登録済み他ユーザー向けの実行では必ず本人のトークンを明示的に渡す

## 公開ダッシュボード用キー（PUBLIC_API_KEY）と管理者用キー（API_KEY）の分離
Vite の `VITE_` 接頭辞の環境変数はビルド時にJSバンドルへ平文で埋め込まれるため、
ダッシュボードに管理者用`API_KEY`（`/admin/*`も保護する単一キー）を設定すると、
誰でもバンドルから抽出して管理操作を実行できてしまう（実際に本番でこの状態が発生し、
キーローテーションで対応したインシデントあり）。読み取り専用エンドポイント
（KEV/OSV/JVN/crawler-logs）だけは`require_public_api_key`（`API_KEY`または
`PUBLIC_API_KEY`のいずれか）で保護し、ダッシュボードの`VITE_PUBLIC_API_KEY`には
`PUBLIC_API_KEY`の値のみを設定する。`/admin/*`は`require_api_key`（`API_KEY`のみ）
のまま。DEPSCANはダッシュボードから`X-API-KEY`を一切送らずセッショントークンのみを
使うため、この分離の対象外。
