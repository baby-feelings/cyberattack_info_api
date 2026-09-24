---
name: codescan
description: CODESCAN（自アプリのコード自体の脆弱性診断、Semgrep静的解析）の内部設計。tarball取得方式・per-repoタイムアウト・CVSS 3.1のベストエフォート推定ロジック・GitHub Issue自動起票・保持期間削除を扱う。app/codescan/・app/core/cvss.py配下の変更時に読む。
---

# CODESCAN 内部実装リファレンス

## CODESCAN は Semgrep で自アプリのソースコード自体を静的解析する（DEPSCANとは別種の検知）
DEPSCAN（`app/depscan/`）が「依存ライブラリの既知脆弱性」を OSV API とリアルタイム照合するのに
対し、CODESCAN（`app/codescan/`）は「自アプリのコード自体に潜む脆弱性パターン」
（SQLi・ハードコード認証情報・XSS等）を Semgrep（`p/security-audit` + `p/secrets`、
Semgrep Registryの無料公開ルールセット）で静的解析する。対象リポジトリ一覧は
DEPSCANと完全に同じ（`GITHUB_USERNAME`配下、fork・archived除外）ため
`app.depscan.github_client.list_target_repos`をそのまま再利用する（DRY原則、
重複実装しない）。

## ソースコード取得は tarball 方式（ファイル単位APIではない）
DEPSCANの`get_repo_tree`/`get_file_content`はファイル単位のAPI呼び出しを要し、
リポジトリ全体のソース取得には非効率。CODESCANは`app.codescan.github_client
.download_repo_tarball`でGitHubの`GET /repos/{owner}/{repo}/tarball/{ref}`
エンドポイントを使い、リポジトリ全体を1回のHTTP呼び出しで取得する（httpxの
`follow_redirects=True`が必須。tarballエンドポイントは302リダイレクト経由で
実データを返す）。取得したtar.gzは`tempfile.TemporaryDirectory()`に展開してから
Semgrepでスキャンし、`with`ブロックを抜ける際に確実に削除される。パストラバーサル
対策として`tarfile.extractall(..., filter="data")`（PEP 706）で安全に展開する
（`app.codescan.crawler._extract_tarball`）。`git`コマンドはDockerイメージに
追加していない（tarball方式なら不要）。

## Semgrep 実行は薄いラッパー関数に分離し、テストはそれをモックする
`app.codescan.crawler._run_semgrep`が実際の`subprocess.run(["semgrep", ...])`
呼び出しを閉じ込める薄いラッパー。1リポジトリあたりのタイムアウトを
`timeout=300`（サブプロセス全体）+ `--timeout 120`（Semgrep内部の1ルール×
1ファイルあたり）の二段で必ず設定する（OCI本番は1 OCPU/6GBの限られたリソース
のため、1リポジトリのスキャンが長時間ブロックすると他のクローラー・CODESCAN
全体を圧迫するリスクがある）。タイムアウト・パース失敗等はリポジトリ単位で
`app.codescan.crawler._run_codescan_body`のtry/exceptによりスキップされ、
CODESCAN全体は継続する（DEPSCANのGitHub API呼び出し失敗時と同じper-repoパターン）。
Windows開発環境にSemgrepバイナリが無くてもテストできるよう、`_run_semgrep`
自体をモックするテスト設計にしている（`tests/codescan/test_crawler.py`）。

## CVSS 3.1 スコアは「ベストエフォートの近似値」であり精度を保証しない
真のCVSS基本値は既知の脆弱性1件ごとに人間がAV/AC/PR/UI/S/C/I/Aを判断するもので、
静的解析結果（ルールID・severity・CWE）だけから機械的に正確なCVSSを算出することは
原理的に不可能。この設計上の限界を前提に、2段階で構成する:

- **`app.core.cvss.calculate_base_score`**: NVD公式のCVSS 3.1計算式をそのまま
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
取得→スキャンするため、`app.codescan.crawler._resolve_stale_repo_findings`は
**そのリポジトリのスキャンが成功した直後に、そのリポジトリだけを対象に**
解決判定を行う設計にした（あるリポジトリのスキャンが失敗してスキップされた場合、
そのリポジトリの既存findingを誤って解決済みにしないため）。

## オーケストレーションは KEV/OSV/JVN と同じ `run_crawler` を使う（DEPSCANとは異なる）
DEPSCANは詳細なSlackダイジェスト（`notify_dependency_findings`）・Issue自動
クローズ判定など独自の複雑なオーケストレーションを持つため`run_crawler`を
使っていないが、CODESCANは`app.core.crawler_runner.run_crawler`（Template Method）
+ `CrawlCounters`をそのまま使い、通知は`notify_success`/`notify_error`の汎用
フォーマットで済ませる設計にした（要件どおり、DRY原則を優先）。`CrawlCounters`
への対応付けはDEPSCANのcrawler_logs記録方針を踏襲: `inserted`=新規検知件数、
`deleted`=今回解決済みにした件数、`updated`=保持期間超過（`CODESCAN_RETENTION_DAYS`、
既定180日）の実削除件数。

## GitHub Issue自動起票はDEPSCANと同じパターンだがタイトルを分離
`app.codescan.issue_management._file_github_issues`は「1リポジトリにつき常に
1つのOpen Issueに集約する」設計をDEPSCANから踏襲するが、Issueタイトルを
`"🔎 自アプリのコード脆弱性が検出されました (CODESCAN)"`という固定文字列にし、
DEPSCANの`"🚨 依存ライブラリの脆弱性が検出されました (DEPSCAN)"`と混同しないように
している。Issue本文の整形は`_format_finding_lines`（severity降順→ファイルパス順）
で行う（DEPSCANのパッケージ単位整形`app.core.finding_format.format_package_lines`
とは検知の粒度が異なるため共有せず、`app.codescan.issue_management`内に個別実装）。
現バージョンでは新規起票・追記のみを実装し、自動クローズ（DEPSCANの
`_close_resolved_repo_issues`相当）は将来の拡張とした（`run_crawler`ベースの
オーケストレーションでは、DEPSCANが行う「全体再スキャン検証後」というクローズ
タイミングの前提が成立しないため）。

## API認証: ログイン必須だがオーナー制限なし（Issue #219でrequire_public_api_keyから変更）
自アプリの内部コード脆弱性は特定ユーザーに紐づく情報ではないため、DEPSCANの
GitHubログインによる「本人所有リポジトリのみ」制限は不要。一方でダッシュボードの
DEPSCAN/CODESCANタブ間でセッションを共有し、CODESCANも読み取りにGitHubログインを
必須にする（要件変更、Issue #219）ため、当初の`require_public_api_key`から
`app.core.auth.require_api_key_or_session`（`X-API-KEY`またはGitHubログイン
セッションJWTのいずれかを要求する共通認証）に変更した。この関数はDEPSCANの
`_resolve_access`と検証ロジックが同一（DRY原則で共通化）だが、CODESCANは戻り値
（セッション認証時はログインユーザー名）を絞り込みには使わず「ログイン済みか」
のみをゲートとして使う。`GET /api/codescan`・`GET /api/codescan/stats`はこの
共通認証で保護する。`POST /admin/codescan-crawl`は他ドメインと同じ`require_api_key`
（`API_KEY`のみ）で変更なし。

フロントエンド側は`DepscanAuthGate.tsx`と共通の`useGithubSession`フック
（`dashboard/src/hooks/useGithubSession.ts`）を使い、`localStorage`のキー
（`depscan_session_token`/`depscan_session_user`）も共有する。これにより
DEPSCAN/CODESCANのどちらのタブでログインしても両方閲覧できる。`CodescanAuthGate.tsx`
はDEPSCANと異なりオンデマンドスキャンの概念が無いため、スキャン進捗ポーリングUIを
持たず、ログイン確認ができたら即座に`CodescanPanel`を表示するシンプルな構成。

## gitleaksによるシークレット検知の統合（Issue #219）
Semgrep（`p/security-audit` + `p/secrets`）に加え、専用のシークレット検知ツール
gitleaks（https://github.com/gitleaks/gitleaks )も同じtarball展開先に対して実行
する。`app.codescan.crawler._run_gitleaks`が`subprocess.run(["gitleaks", "detect",
"--source", ..., "--no-git", "--report-format", "json", "--report-path", ...,
"--exit-code", "0"])`を呼ぶ薄いラッパー（Semgrepと同じ「ラッパー自体をモックして
テストする」方針）。`--no-git`必須（tarball展開のためGit履歴が無く、gitleaksを
ファイルシステムスキャンモードで動かす）。`--exit-code 0`でリーク検知時の非ゼロ
終了を防ぎ、Semgrepと同様「検知があっても正常終了として扱いJSON出力をパースする」
設計に統一している。gitleaksの結果はサブプロセス全体で120秒のタイムアウトを持つ
（Semgrepの300秒より短い。正規表現ベースのシークレット検知は一般にSemgrepの
パターンマッチよりも高速なため）。

**Semgrepとgitleaksは独立したtry/exceptで囲む**（`_scan_repo`）。1つのtry/except
で両方を囲むと、片方の障害（タイムアウト・パース失敗等）でもう片方の正常な検知結果
まで丸ごと失ってしまうため、意図的に分離している。

**Upsertキーの衝突回避**: `CodeFinding`のUpsert基準キー`(repo_full_name,
file_path, rule_id, line_start)`は据え置きだが、gitleaks由来のfindingは
`rule_id`に`"gitleaks:"`プレフィックスを付与する（`_parse_gitleaks_results`）。
SemgrepのcheckID（`python.lang.security....`のような命名規則）との衝突リスクは
低いが、明示的にツール由来を区別できるようにするため。`CodeFinding.tool`カラム
（`"semgrep"` / `"gitleaks"`、既存レコードとの後方互換のため`server_default=
"semgrep"`）でも区別でき、ダッシュボードの`CodescanRow.tsx`にはツール種別を示す
小さなバッジを表示する。

**【重要・セキュリティ】シークレット値は絶対にDB・APIレスポンスに含めない**:
gitleaksのJSON出力には検知したシークレットの実際の値（`Secret`フィールド、
マッチした認証情報そのもの）が平文で含まれる。これをそのまま保存・返却すると、
自アプリの脆弱性診断APIが実際の認証情報を漏洩させるという本末転倒な事故になる。
そのため`_parse_gitleaks_results`は`Secret`・`Match`フィールドを一切参照せず、
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
バイナリが無い前提でテストは`_run_gitleaks`自体をモックして書く。

**ファイルパスはrepo_root基準の相対パスへ正規化する（Issue #222で発覚したバグ）**:
gitleaksのJSON出力の`File`フィールドは、環境によってはtarball展開先の絶対パス
（`tempfile.TemporaryDirectory()`が毎回生成するランダムなディレクトリ名を含む）
をそのまま返す。これをUpsertキーの`file_path`にそのまま使うと、
`tempfile.TemporaryDirectory()`のパスがスキャンごとに変わるためUpsertの自然キー
が毎回一致せず、findingが際限なく重複蓄積する実害があった（本番データで発覚）。
`_parse_gitleaks_results(full_name, gitleaks_results, repo_root)`は`repo_root`
引数を受け取り、`File`が絶対パスの場合のみ`os.path.relpath(raw_path, repo_root)`
で相対パスへ正規化する（`_parse_semgrep_results`が元々行っていたのと同じパターン
に合わせた）。

**リポジトリ単位のgitleaks allowlist自動検出（Issue #221）**: gitleaksは
`--source`配下の設定ファイルを自動探索しない（Semgrepとは異なる挙動）ため、
明示的に`--config`で渡さない限りデフォルトルールのみが適用される。本リポジトリ
自身がCODESCANのスキャン対象に含まれる場合、`tests/codescan/test_crawler.py`内の
テスト用ダミーシークレットまで誤検知してしまい、スキャンのたびにGitHub Issueが
再起票され続ける問題が実際に発生した。対応として`_run_gitleaks(target_dir)`が
`target_dir`直下に`.gitleaks.toml`が存在するかを`os.path.isfile`で確認し、
存在すれば`["--config", repo_config_path]`をコマンドに追加する。これにより
CODESCANのスキャン対象となる各baby-feelingsリポジトリが、自分自身の
`.gitleaks.toml`（`[[allowlist]] paths = [...]`）で既知の誤検知を個別に
allowlist登録できる、リポジトリ非依存の汎用的な仕組みになっている（本リポジトリ
ルートの`.gitleaks.toml`もこの仕組みで自分自身のテストフィクスチャを除外している）。
