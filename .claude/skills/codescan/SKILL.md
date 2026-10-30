---
name: codescan
description: CODESCAN（自アプリのコード自体の脆弱性診断、Semgrep静的解析）の内部設計。tarball取得方式・per-repoタイムアウト・CVSS 3.1のベストエフォート推定ロジック・GitHub Issue自動起票・保持期間削除を扱う。app/codescan/・app/codescan/cvss.py配下の変更時に読む。
---

# CODESCAN 内部実装リファレンス

## CODESCAN は Semgrep で自アプリのソースコード自体を静的解析する（DEPSCANとは別種の検知）
DEPSCAN（`app/depscan/`）が「依存ライブラリの既知脆弱性」を OSV API とリアルタイム照合するのに
対し、CODESCAN（`app/codescan/`）は「自アプリのコード自体に潜む脆弱性パターン」
（SQLi・ハードコード認証情報・XSS等）を Semgrep（`p/security-audit` + `p/secrets`、
Semgrep Registryの無料公開ルールセット）で静的解析する。対象リポジトリ一覧は
DEPSCANと完全に同じ（`GITHUB_USERNAME`配下、fork・archived除外）ため
`app.core.github.accounts.list_target_repos`をそのまま再利用する（DRY原則、
重複実装しない。CODESCANはDEPSCANに依存せず、共通部分は`core/github`にある）。

## 構成（役割ごとのモジュール）
`crawler.py`は走査の組み立てだけ（`scan_repo`・`_run_codescan_body`・`fetch_and_scan_code`）。実装は役割ごとに分かれる:
`archive.py`（`RepoArchive`=tarballの展開と一時ディレクトリの削除）・`scanners.py`（`Scanner`の
Strategy: `SemgrepScanner`/`GitleaksScanner`。`run`=ツール実行、`parse`=レコード化、`scan`=その連結。
ツールを足すときは`Scanner`を継承して`default_scanners`に加える）・`repository.py`
（`CodeFindingRepository`: `sync`=Upsert+検知されなくなったものを解決済みに、`delete_old_resolved`）。
`SCAN_ERRORS`（1リポジトリの検査で起こりうる例外の組）は`crawler.py`の毎日実行と`user_scan.py`が共有する。

## ソースコード取得は tarball 方式（ファイル単位APIではない）
`GitHubRepo.tree`/`file_content`はファイル単位のAPI呼び出しを要し、
リポジトリ全体のソース取得には非効率。CODESCANは`GitHubRepo.tarball`
（`app.core.github.repo`）でGitHubの`GET /repos/{owner}/{repo}/tarball/{ref}`
エンドポイントを使い、リポジトリ全体を1回のHTTP呼び出しで取得する（httpxの
`follow_redirects=True`が必須。tarballエンドポイントは302リダイレクト経由で
実データを返す）。取得したtar.gzは`tempfile.TemporaryDirectory()`に展開してから
Semgrepでスキャンし、`with`ブロックを抜ける際に確実に削除される。パストラバーサル
対策として`tarfile.extractall(..., filter="data")`（PEP 706）で安全に展開する
（`app.codescan.archive.extract_tarball`（`RepoArchive`が一時ディレクトリの削除まで担う））。`git`コマンドはDockerイメージに
追加していない（tarball方式なら不要）。

## semgrep は専用venvに隔離して導入する（requirements.txtに入れない）
semgrep は `subprocess` で呼ぶ外部CLIでありPythonからimportしないため、アプリの依存
（`requirements.txt`）ではなく`semgrep-cli.txt`に置き、`Dockerfile`で専用venv
（`/opt/semgrep-venv`）へ導入して`/usr/local/bin/semgrep`にsymlinkする。理由: semgrep は
`pyjwt~=2.13.0`・`mcp`・`click`等を厳密にピン留めするため、同じ環境だとアプリのPyJWTを
脆弱性修正済み（2.15以降）に上げられず、semgrepを古い版に固定すると`mcp`/`click`側の別の
脆弱性が出た（2026-09の PyJWT 26件の対応時、pip-auditで確認）。venv内のPyJWTだけは
Dockerfileで`>=2.15.1`に上書きしている（pip checkは警告するがsemgrep 1.178.0で動作確認済み）。
`semgrep-cli.txt`を`requirements*.txt`にしない理由は、pip-audit/OSV-Scannerの走査対象を
アプリ本体の依存に限定するため。semgrepを上げる際はDockerfileの上書きが不要になっていないか
（semgrep側のpyjwtピンが2.15以降を許容したか）も確認する。Windowsにはsemgrepのホイールが無く、
開発環境ではラッパーをモックする。

## Semgrep 実行は薄いラッパー関数に分離し、テストはそれをモックする
`app.codescan.scanners.SemgrepScanner.run`が実際の`subprocess.run(["semgrep", ...])`
呼び出しを閉じ込める薄いラッパー。1リポジトリあたりのタイムアウトを
`timeout=300`（サブプロセス全体）+ `--timeout 120`（Semgrep内部の1ルール×
1ファイルあたり）の二段で必ず設定する（OCI本番は1 OCPU/6GBの限られたリソース
のため、1リポジトリのスキャンが長時間ブロックすると他のクローラー・CODESCAN
全体を圧迫するリスクがある）。タイムアウト・パース失敗等はリポジトリ単位で
`app.codescan.crawler._run_codescan_body`のtry/exceptによりスキップされ、
CODESCAN全体は継続する（DEPSCANのGitHub API呼び出し失敗時と同じper-repoパターン）。
Windows開発環境にSemgrepバイナリが無くてもテストできるよう、`SemgrepScanner.run`
自体をモックするテスト設計にしている（`tests/codescan/test_crawler.py`）。

## CVSS 3.1 スコアは「ベストエフォートの近似値」であり精度を保証しない
真のCVSS基本値は既知の脆弱性1件ごとに人間がAV/AC/PR/UI/S/C/I/Aを判断するもので、
静的解析結果（ルールID・severity・CWE）だけから機械的に正確なCVSSを算出することは
原理的に不可能。この設計上の限界を前提に、2段階で構成する:

- **`app.codescan.cvss.calculate_base_score`**: NVD公式のCVSS 3.1計算式をそのまま
  実装した、ベクター文字列→スコアの正式な変換ロジック（Impact/Exploitability
  サブスコア・Scope分岐・Roundup関数を含む）。ここ自体は近似ではなく厳密な実装。
- **`app.codescan.cvss_mapping.estimate_cvss_vector`**: Semgrepのseverity・CWEから
  ベクター文字列をベストエフォートで推定する部分（ここが近似）。ネットワークから
  直接攻撃可能かを機械的に判定するのは困難なため、保守的にAV:Nをデフォルトとし、
  CWE-798（ハードコード認証情報）のようにソース閲覧が前提と明確に判断できる
  カテゴリのみAV:Lに調整する。既知の代表的CWE（798/89/78/79/327/326/22）には
  個別ベクターをハードコードし、未知CWE・CWE情報なしはseverityベースの粗い
  フォールバック（ERROR>WARNING>INFO の順にC/I/Aを下げる）を使う。

CVSS 7.0以上はダッシュボード（`CodescanRow.tsx`のCvssBadge）で赤バッジ強調表示する。

## Upsertキー・解決判定はリポジトリ単位（DEPSCANの全体横断方式とは異なる）
`CodeFinding`のUpsert基準キーは`(repo_full_name, file_path, rule_id, line_start)`
の複合ユニーク制約（Semgrepには安定した検知ID的なものが無いため）。DEPSCANは
「今回の全リポジトリ横断スキャンで検知されなくなったfinding」を一括で解決済みに
するが、CODESCANは`_run_codescan_body`のループ内でリポジトリを1つずつtarball
取得→スキャンするため、`app.codescan.repository.CodeFindingRepository.resolve_stale`は
**そのリポジトリのスキャンが成功した直後に、そのリポジトリだけを対象に**
解決判定を行う設計にした（あるリポジトリのスキャンが失敗してスキップされた場合、
そのリポジトリの既存findingを誤って解決済みにしないため）。

## オーケストレーションは KEV/OSV/JVN と同じ `run_crawler` を使う
DEPSCANは詳細なSlackダイジェスト（`notify_dependency_findings`）・Issue自動
クローズ判定など固有の通知・戻り値を持つため`CrawlJob`のサブクラス（`_DepscanJob`）で
実装しているが、CODESCANは`app.core.crawler_runner.run_crawler`（`CrawlJob`のラッパー）
+ `CrawlCounters`をそのまま使い、通知は`notify_success`/`notify_error`の汎用
フォーマットで済ませる設計にした（要件どおり、DRY原則を優先）。`CrawlCounters`
への対応付けはDEPSCANのcrawler_logs記録方針を踏襲: `inserted`=新規検知件数、
`deleted`=今回解決済みにした件数、`updated`=保持期間超過（`CODESCAN_RETENTION_DAYS`、
既定180日）の実削除件数。

## GitHub Issue自動起票はDEPSCANと共通処理を共有、タイトルと本文整形のみ分離
「リポジトリ単位でグルーピング→Open Issue検索→追記または新規作成→API失敗は
握りつぶす」という手順自体はDEPSCANの`app.depscan.issue_management`と完全に
同一のため、`app.core.issue_filing.file_or_update_repo_issues`に共通化されている。
`app.codescan.issue_management.file_github_issues`はこの共通処理へ、Issueタイトル
`"🔎 自アプリのコード脆弱性が検出されました (CODESCAN)"`（DEPSCANの
`"🚨 依存ライブラリの脆弱性が検出されました (DEPSCAN)"`と混同しないための固定文字列）と
本文整形関数`_format_finding_lines`（severity降順→ファイルパス順）を渡すだけの
薄い実装になっている。本文整形をDEPSCANの`app.core.finding_format.format_package_lines`
と共有しないのは、検知の粒度（パッケージ単位 vs ファイル:行単位）が異なるため。
現バージョンでは新規起票・追記のみを実装し、自動クローズ（DEPSCANの
`close_resolved_repo_issues`相当）は将来の拡張とした（`run_crawler`ベースの
オーケストレーションでは、DEPSCANが行う「全体再スキャン検証後」というクローズ
タイミングの前提が成立しないため）。

## API認証: ログイン必須かつ本人所有リポジトリのみ（Issue #219でログイン必須化、#289で絞り込み追加）
ダッシュボードのDEPSCAN/CODESCANタブ間でセッションを共有し、CODESCANも読み取りにGitHubログインを
必須にする（Issue #219）ため、`app.auth.api_key.require_api_key_or_session`（`X-API-KEY`または
GitHubログインセッションJWTのいずれかを要求する共通認証。DEPSCANの`_resolve_access`と共通、DRY）で
`GET /api/codescan`・`/stats`を保護する。

**セッション認証時は戻り値（ログインユーザー名）で本人所有リポジトリのみに強制的に絞り込む**
（`flt.restrict_to_owner(forced_owner)`・statsは`repo_full_name LIKE '<user>/%'`）。当初は「内部コード
脆弱性は特定ユーザーに紐づかない」として絞り込まず、ログインさえすれば任意のGitHubユーザーが全
リポジトリの検知結果（リポジトリ名・脆弱箇所）を取得できたが、他の人に見せてはならないため
DEPSCANと同じ方式に揃えた（`repo`で他人のリポジトリを指定すると403）。`X-API-KEY`（`API_KEY`）は
従来どおり絞り込まない。`POST /admin/codescan-crawl`は`require_api_key`（`API_KEY`のみ）で変更なし。
リモートMCPサーバー（`docs/mcp-server.md`）も同じREST経路を使うため同じ絞り込みが効く。

フロントエンド側は`DepscanAuthGate.tsx`と共通の`useGithubSession`フック
（`dashboard/src/hooks/useGithubSession.ts`）を使い、`localStorage`のキー
（`depscan_session_token`/`depscan_session_user`）も共有する。これにより
DEPSCAN/CODESCANのどちらのタブでログインしても両方閲覧できる。`CodescanAuthGate.tsx`
はDEPSCANと異なりオンデマンドスキャンの概念が無いため、スキャン進捗ポーリングUIを
持たず、ログイン確認ができたら即座に`CodescanPanel`を表示するシンプルな構成。

## gitleaksによるシークレット検知の統合（Issue #219）
Semgrep（`p/security-audit` + `p/secrets`）に加え、専用のシークレット検知ツール
gitleaks（https://github.com/gitleaks/gitleaks )も同じtarball展開先に対して実行
する。`app.codescan.scanners.GitleaksScanner.run`が`subprocess.run(["gitleaks", "detect",
"--source", ..., "--no-git", "--report-format", "json", "--report-path", ...,
"--exit-code", "0"])`を呼ぶ薄いラッパー（Semgrepと同じ「ラッパー自体をモックして
テストする」方針）。`--no-git`必須（tarball展開のためGit履歴が無く、gitleaksを
ファイルシステムスキャンモードで動かす）。`--exit-code 0`でリーク検知時の非ゼロ
終了を防ぎ、Semgrepと同様「検知があっても正常終了として扱いJSON出力をパースする」
設計に統一している。gitleaksの結果はサブプロセス全体で120秒のタイムアウトを持つ
（Semgrepの300秒より短い。正規表現ベースのシークレット検知は一般にSemgrepの
パターンマッチよりも高速なため）。

**Semgrep・gitleaks・zizmorは独立したtry/exceptで囲む**（`scan_repo`）。1つのtry/except
で全部を囲むと、1つの障害（タイムアウト・パース失敗等）でほかの正常な検知結果
まで丸ごと失ってしまうため、意図的に分離している。
**既知の弱点**: 失敗したツールの検知は、そのスキャンの結果に含まれないため、`sync`が
「検知されなくなった」とみなして解決済みにする（次に成功すると、新規検知として再起票される）。

## zizmorによるGitHub Actionsワークフローの診断（Issue #397、`ZizmorScanner`）
CIは供給網の一部で、ワークフローの不備はシークレットの窃取・改ざんにつながる（2025年の
`tj-actions/changed-files`の事例）。同じtarball展開先の`.github/workflows/`等を診断する。
- **実行**: `zizmor --offline --persona auditor --format json --no-exit-codes --quiet .`を、展開先を
  `cwd`にして実行（パスをリポジトリ基準の相対にするため）。**オフライン**（トークン不要・APIレート制限なし）の
  ため、オンライン診断（既知の脆弱なアクション・偽造コミットの参照）は含まない。Dockerfileの専用venv
  （`zizmor-cli.txt`、`~=1.31`）。出力形式は実物で確認済み（`locations[].symbolic.key.Local.verbatim_path`・
  行は**0始まり**・`determinations.severity`/`persona`・`ignored`）
- **ワークフローが無いリポジトリは、終了コード3・標準出力なし**（stderrに`no inputs collected`）。エラーでなく
  「検知なし」として扱う。**それ以外で出力が無い場合は`OSError`**（0件として扱うと既存の検知を解決済みにするため）
- **検査レベル**: `auditor`で実行し、`persona`が`Regular`の指摘と、`self-hosted-runner`（auditor分類だが
  使用の把握が必要）だけを取り込む。他のauditor・pedanticの指摘はノイズのため除く
- **重要度**: High→ERROR・Medium→WARNING・それ以外→INFO（Semgrepと同じ尺度）。**CVSS・CWEは推定しない**
  （脆弱性そのものでなく設定の不備のため）。`rule_id`は`zizmor:<指摘名>`、`tool`は`"zizmor"`
- メッセージに修正方法（`_ZIZMOR_FIX_HINTS`: 未固定アクション・過剰な権限・危険なトリガー・コマンド注入・
  セルフホストランナー等）と、zizmorの説明URLを添える。`# zizmor: ignore[...]`の指摘（`ignored`）は除く
- `hardcoded-container-credentials`は、認証情報が書かれうるため**スニペットを保存しない**（gitleaksと同じ方針）
- ダッシュボードは`CodescanRow.tsx`のツールバッジ（Zizmor）。最初のスキャンでは、既存のワークフローの指摘が
  まとめて新規検知になり、リポジトリごとのGitHub Issueが起票・追記される

**Upsertキーの衝突回避**: `CodeFinding`のUpsert基準キー`(repo_full_name,
file_path, rule_id, line_start)`は据え置きだが、gitleaks由来のfindingは
`rule_id`に`"gitleaks:"`プレフィックスを付与する（`GitleaksScanner.parse`）。
SemgrepのcheckID（`python.lang.security....`のような命名規則）との衝突リスクは
低いが、明示的にツール由来を区別できるようにするため。`CodeFinding.tool`カラム
（`"semgrep"` / `"gitleaks"`、既存レコードとの後方互換のため`server_default=
"semgrep"`）でも区別でき、ダッシュボードの`CodescanRow.tsx`にはツール種別を示す
小さなバッジを表示する。

**【重要・セキュリティ】シークレット値は絶対にDB・APIレスポンスに含めない**:
gitleaksのJSON出力には検知したシークレットの実際の値（`Secret`フィールド、
マッチした認証情報そのもの）が平文で含まれる。これをそのまま保存・返却すると、
自アプリの脆弱性診断APIが実際の認証情報を漏洩させるという本末転倒な事故になる。
そのため`GitleaksScanner.parse`は`Secret`・`Match`フィールドを一切参照せず、
`code_snippet`相当のフィールドには gitleaks の`Description`（ルールの説明。例:
「AWS Access Key」）のみを固定文言「検知内容: {Description}」として格納する。
`tests/codescan/test_crawler.py`の`TestParseGitleaksResults`に、実際のシークレット
値がレコードのどのフィールドにも含まれないことを検証する専用テストがある。

**CVSS推定**: gitleaksの検知はハードコードされた認証情報（CWE-798）に相当する
ため、Semgrep実装時に用意済みの`app.codescan.cvss_mapping`のCWE-798マッピング
（`AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`）をそのまま再利用する（新規ロジック不要、
DRY原則）。severityの概念がgitleaksには無いため、常に`estimate_cvss_vector("ERROR",
["CWE-798"])`として扱う。

**Dockerfileへのバイナリ導入**: gitleaksはGo製バイナリのためpipでは導入できず、
GitHub Releasesから本番環境（OCI Ampere A1 = Linux ARM64）向けのプリビルド
バイナリ（`gitleaks_<version>_linux_arm64.tar.gz`）を`curl`で取得し
`/usr/local/bin/gitleaks`に配置する。`latest`タグは使わずARG（`GITLEAKS_VERSION`）
でバージョンを固定する。バージョンを上げる場合は
https://api.github.com/repos/gitleaks/gitleaks/releases/latest で最新版を確認し、
Dockerfileの`ARG GITLEAKS_VERSION`を更新すること。Windows開発環境にはgitleaks
バイナリが無い前提でテストは`GitleaksScanner.run`自体をモックして書く。

**ファイルパスはrepo_root基準の相対パスへ正規化する（Issue #222で発覚したバグ）**:
gitleaksのJSON出力の`File`フィールドは、環境によってはtarball展開先の絶対パス
（`tempfile.TemporaryDirectory()`が毎回生成するランダムなディレクトリ名を含む）
をそのまま返す。これをUpsertキーの`file_path`にそのまま使うと、
`tempfile.TemporaryDirectory()`のパスがスキャンごとに変わるためUpsertの自然キー
が毎回一致せず、findingが際限なく重複蓄積する実害があった（本番データで発覚）。
`GitleaksScanner.parse(full_name, raw, repo_root)`は`repo_root`
引数を受け取り、`File`が絶対パスの場合のみ`os.path.relpath(raw_path, repo_root)`
で相対パスへ正規化する（`SemgrepScanner.parse`が元々行っていたのと同じパターン
に合わせた）。

**リポジトリ単位のgitleaks allowlist自動検出（Issue #221）**: gitleaksは
`--source`配下の設定ファイルを自動探索しない（Semgrepとは異なる挙動）ため、
明示的に`--config`で渡さない限りデフォルトルールのみが適用される。本リポジトリ
自身がCODESCANのスキャン対象に含まれる場合、`tests/codescan/test_crawler.py`内の
テスト用ダミーシークレットまで誤検知してしまい、スキャンのたびにGitHub Issueが
再起票され続ける問題が実際に発生した。対応として`GitleaksScanner.run(target_dir)`が
`target_dir`直下に`.gitleaks.toml`が存在するかを`os.path.isfile`で確認し、
存在すれば`["--config", repo_config_path]`をコマンドに追加する。これにより
CODESCANのスキャン対象となる各baby-feelingsリポジトリが、自分自身の
`.gitleaks.toml`（`[[allowlist]] paths = [...]`）で既知の誤検知を個別に
allowlist登録できる、リポジトリ非依存の汎用的な仕組みになっている（本リポジトリ
ルートの`.gitleaks.toml`もこの仕組みで自分自身のテストフィクスチャを除外している）。

**Semgrepの誤検知除外は`.semgrepignore`（コード側の実装不要）**: gitleaksとは異なり
Semgrepは`--source`配下の`.semgrepignore`（`.gitignore`と同じgitignore構文）を
標準機能として自動的に尊重するため、gitleaksの`.gitleaks.toml`自動検出のような
コード側の対応は不要。誤検知1件を1行で除外したい場合は対象コード行に
`# nosemgrep`（またはルールID指定で`# nosemgrep: <rule-id>`）を付与する方法もあり、
ファイル全体を除外したい場合（Jekyllサイトの`_includes/*.html`のような、静的な
テンプレート変数を汎用ルールが誤検知するケース等）は`.semgrepignore`にパスを
1行追加する方法を使う。いずれもリポジトリ側の対応のみで完結し、CODESCAN本体の
コード変更は不要（baby-feelings傘下の複数リポジトリで、Firebase/GCPクライアント
APIキー〈`.gitleaks.toml`〉・Jekyllテンプレート変数〈`.semgrepignore`〉・自リポジトリの
defusedxml誤検知〈`# nosemgrep`〉の3パターンで実際に運用している）。

**`# nosemgrep`は、指摘される行の「すぐ上の行」に置く**（間に別のコメント行を挟むと効かず、CODESCANの再スキャンで
同じ検知が残る。2026-10-26、babysmile_iyricsで発生）。説明のコメントは`# nosemgrep`の上に書く。
手元で検知を再現・確認するときは、CODESCANと同じ設定（`semgrep --config=p/security-audit --config=p/secrets`）で実行する。
`--config p/python`など別のルールセットでは0件になり、見逃す。

## 自リポジトリの `.gitleaks.toml`（allowlist）の書式
`GitleaksScanner.run`は対象リポジトリのルートに`.gitleaks.toml`があれば`--config`で渡す。**gitleaks 8.xは
allowlistを「テーブル」`[allowlist]`として読む**。配列`[[allowlist]]`だと`expected a map, got slice`で
設定の読み込み自体に失敗する（本リポジトリで実際に発生。PRのgitleaks CIで発覚）。複数の除外を書く
場合は`[[allowlists]]`（複数形、8.25以降）を使う。除外が効くことは`docker run ghcr.io/gitleaks/gitleaks
:v8.30.1 git --log-opts="--all -- <path>" /repo`で確認できる（`dir`モードは設定を対象ディレクトリ内で
探すためリポジトリルートの設定が使われない点に注意）。
