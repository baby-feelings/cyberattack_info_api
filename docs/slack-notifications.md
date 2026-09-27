# Slack 通知の設定（Issue #227：ユーザー別登録制）

[README.md](../README.md) から分離した詳細ページ。固定の `SLACK_WEBHOOK_URL` 環境変数は
廃止し、**各ユーザーがダッシュボードから自分の Slack Webhook を登録する方式**に変更した。

1. [Slack App Directory](https://your-workspace.slack.com/apps/A0F7XDUAZ-incoming-webhooks) で「Incoming WebHooks」を追加し、通知先チャンネルを選択して Webhook URL を取得
2. ダッシュボードのヘッダー右上のハンバーガーメニュー →「設定」から GitHub アカウントでログインし、取得した Webhook URL を貼り付けて「テスト送信して保存」を押す（実際にテスト通知を送信し、成功した場合のみ登録される）
3. `GITHUB_USERNAME`（`baby-feelings`）自身の毎日クロールの通知を引き続き受け取りたい場合も、`GITHUB_USERNAME` と同じ GitHub アカウントでログインしてこの画面から登録が必要（過去の `SLACK_WEBHOOK_URL` の値は自動移行されない）

## 通知先の解決ルール

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

## GitHub Issue 自動起票（DEPSCAN / CODESCAN）

Slack 通知に加えて、DEPSCAN・CODESCAN の新規検知は検知されたリポジトリ自身に GitHub Issue としても自動起票される。

- タイトル固定。DEPSCAN: `🚨 依存ライブラリの脆弱性が検出されました (DEPSCAN)` / CODESCAN: `🔎 自アプリのコード脆弱性が検出されました (CODESCAN)`（両者は文字列で区別され混同しない）。同名の Open な Issue が既にあればコメントを追記し、無ければ新規作成する（1リポジトリにつき常に1つの Open Issue に集約）
- DEPSCANの本文は Slack と同じくパッケージ単位に集約した形式。CODESCANの本文はファイル・行・ルールID・CVSS単位（重要度降順）に整形
- `GITHUB_TOKEN` に `Issues: Write` 権限が無い場合、Issue 作成のみ失敗しログに警告が残る（DEPSCAN/CODESCAN 自体は成功扱い）

**Issue の自動クローズ（DEPSCANのみ）:** その後の再スキャンで、対象リポジトリの未解決 finding が実際に0件に
なったことを確認できると、Open な DEPSCAN Issue へ解決を報告するコメントを追加した上で自動的に
クローズする。トリガーは DEPSCAN の再スキャンでの検証後であり、Dependabot PR をマージした
直後には（本当に解消されたか未検証のため）クローズしない。CODESCANは現バージョンでは自動起票・追記のみで、
自動クローズは未実装（Issue側で手動運用）。
