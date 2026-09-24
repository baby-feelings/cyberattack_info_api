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

## API認証はDEPSCANと異なりオーナー制限なし（KEV/OSV/JVNと同じ扱い）
自アプリの内部コード脆弱性は特定ユーザーに紐づく情報ではないため、DEPSCANの
GitHubログインによる「本人所有リポジトリのみ」制限は不要。`GET /api/codescan`・
`GET /api/codescan/stats`は`app.core.auth.require_public_api_key`（読み取り専用、
`API_KEY`または`PUBLIC_API_KEY`）で保護する。`POST /admin/codescan-crawl`は
他ドメインと同じ`require_api_key`（`API_KEY`のみ）。
