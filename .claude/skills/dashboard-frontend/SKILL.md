---
name: dashboard-frontend
description: Reactダッシュボード（dashboard/）のアーキテクチャ設計判断。タブ切り替えUI、KEV/OSV/JVN/DEPSCAN/CODESCAN共通パーツ（VulnPanelParts）、DepscanPanelの集約・オーナーフィルター、DEPSCAN/CODESCAN共有GitHubログイン（useGithubSession）、ハンバーガーメニューからのユーザー別Slack通知登録画面（SettingsPanel、Issue #227）、CSSカスケードレイヤーの注意点、環境表示の日本語化を扱う。dashboard/配下のコンポーネント変更時に読む。
---

# ダッシュボード（React）内部実装リファレンス

## タブ切り替え UI（App.tsx）
KEV / OSV / JVN / DEPSCAN / CODESCAN の 5 データソースは、画面下部固定のタブバーで切り替え
表示する構成（縦並び表示ではない）。DEPSOPS（Dependabot 運用状況）に専用タブは作らず、DEPSCAN
タブ内のボタンから開く全画面モーダルとして統合している。
`TabKey` / `TABS` 定数と `activeTab` state で選択中セクションのみを条件レンダリングし、
サーバー稼働状況（`HealthStatus`）とエラーバナーは全タブ共通で常に表示する。
タブには `role="tablist"/"tab"/"tabpanel"` と `aria-selected`/`aria-controls`/`aria-labelledby` を付与済み。

## KevPanel/OsvPanel/JvnPanel の共通パーツと分割構成
`dashboard/src/components/shared/` に、各パネルで共通の`Badge.tsx`（`SeverityBadge`）・
`ChartParts.tsx`（`ChartCard`/`SeverityPieChart`/`MonthlyBarChart`）・
`TableControls.tsx`（`TableLoadingSkeleton`/`EmptyState`/`Pagination`/
`SeverityFilterButtons`/`SearchBox`/`SortSelector`）に切り出し済み
（`VulnPanelParts.tsx`は元々これら全てを持つ単一ファイルだったが、責務分割のため
3ファイルに分割した。既存のexport名・props型は変えていない）。
深刻度の値・配色（OSV: CRITICAL/HIGH/MEDIUM/LOW、JVN: High/Medium/Low、CODESCAN:
ERROR/WARNING/INFO）はドメイン固有のため `classMap`/`colorMap` として呼び出し側から渡す。
`SeverityBadge`/`SeverityFilterButtons`には任意の`labels`propsも追加済みで、値そのもの
（フィルタでAPIに送る値・データ本体）は変えずに表示テキストだけ上書きできる。CODESCANの
ERROR/WARNING/INFOは「ERRORがシステムエラーのように見えて紛らわしい」という指摘を受け、
CODESCANの呼び出し側だけで`labels={{ ERROR: '重大', WARNING: '警告', INFO: '情報' }}`を
渡して日本語表示にしている（DEPSCAN/OSV/JVN/KEVは`labels`未指定のまま、既存の英語表示を維持）。

行コンポーネント（`KevRow`/`OsvRow`/`JvnRow`）とグラフコンポーネント
（`VendorBarChart`/`EcosystemBarChart`）はドメイン固有のため、`DepscanGroupRow`/`RepoBarChart`
（`components/depscan/`）に倣い `components/{kev,osv,jvn}/` 配下に切り出している。深刻度バッジの
配色（`SEVERITY_CLS`）は各 Panel の重要度フィルターボタンでも使うため Panel 側に残し、Row
コンポーネントには `severityClassMap` として props で渡す。Recharts の Tooltip `formatter` は
jsdom 上でホバーをシミュレートしてもテストから呼び出されないため、
`formatVendorTooltipValue` のように名前付き関数として切り出しテストから直接呼び出す。

`ChartCard` の `footer` スロットは高さ固定領域の**外側**に描画されるため、円グラフの凡例のように
高さ制約に含めたくないコンテンツはここに渡すこと。

`DepscanPanel`/`OsvPanel`は、データ取得・ポーリング・フィルタ状態管理のロジックをそれぞれ
`components/depscan/useDepscanData.ts`・`components/osv/useOsvData.ts`（カスタムフック）に
抽出済み。Panel本体はUIレンダリングに専念する。

## DepscanPanel のオーナーフィルターは repo_full_name から導出
`GET /api/depscan` にリポジトリオーナー絞り込み用の `owner` クエリパラメータがある
（`repo_full_name LIKE '{owner}/%'`。既存の `repo`（完全一致）とは別軸）。オーナーの選択肢
自体は `useDepscanData.ts` 側で `stats.repos`（`/api/depscan/stats` が返す未解決リポジトリ一覧）
から `repo_full_name.split('/')[0]` を抽出して動的に生成しており、専用の一覧APIは無い。
これは DEPSCAN が実際にスキャンした（＝DB に保存済みの）リポジトリのみを反映するため、
`GITHUB_TOKEN` の権限外のリポジトリ情報が混入することはない。オーナーが1種類のみの場合は
フィルターボタン自体を非表示にする（現状 `baby-feelings` のみのため）。

## DepscanPanel はパッケージ×バージョン単位に集約して表示する（クライアント側集約）
`GET /api/depscan` は「パッケージ×CVE」単位で1件返す仕様（`DependencyFinding` の
ユニークキーが `(repo_full_name, ecosystem, package_name, osv_id)` のため）。1パッケージに
複数の CVE が紐づく場合、そのままテーブル表示すると「実際のパッケージ数よりずっと多い件数」
に見えてしまい、Dependabot の PR 数（パッケージ単位で1PR）と数字が食い違って見える問題が
あった。これを解消するため、`fetchAllDepscanFindings`（`per_page=200` でページングしながら
現在のフィルタ条件に一致する全件を取得）でデータを丸ごと取得し、
`(repo_full_name, package_name, installed_version)` 単位にクライアント側でグルーピングして
から表示する。ページネーションもグルーピング後の配列に対してクライアント側で行う
（サーバー側の `page`/`per_page` はこの集約目的にのみ使う）。ヘッダーの件数表示は
「CVE総数 / パッケージ数」の両方を出す。

## DEPSCAN/CODESCANのGitHubログインセッション共有（useGithubSession）
DEPSCAN・CODESCANはともにGitHubログイン必須（要件、Issue #219）で、どちらのタブで
ログインしても両方閲覧できるようセッションを共有する。共通のOAuthコールバック消費・
`localStorage`読み書き（キー名`depscan_session_token`/`depscan_session_user`。
CODESCAN追加後もキー名はあえて変更せず両ドメインで共有する）は
`dashboard/src/hooks/useGithubSession.ts`に抽出済み。`DepscanAuthGate.tsx`は
オンデマンドスキャンの進捗ポーリングUIを持つため`useGithubSession(onLogout)`に
ログアウト時のコールバックを渡すが、**このコールバックは呼び出し側で`useCallback`により
参照を安定させること**。インライン関数（`() => setScanStatus(null)`）のまま渡すと
毎レンダリングで参照が変わり、フック内部の`handleLogout`（`useCallback`で依存配列に
含む）も毎回変わり、それに依存するポーリング`useEffect`が毎レンダリングで再実行されて
`tick()`が多重に走る不具合が実際に発生した（CIのテストで断続的なクラッシュとして顕在化）。
`CodescanAuthGate.tsx`はオンデマンドスキャンの概念が無いため`useGithubSession()`を
引数無しで呼び、ログイン確認後は即座に`CodescanPanel`を表示するだけのシンプルな構成。

`SettingsPanel.tsx`（Issue #227: ユーザー別Slack通知登録画面）も同じ`useGithubSession()`
を引数無しで呼ぶ第三の利用箇所。ヘッダー右上のハンバーガーメニュー（`App.tsx`の
`menuOpen`/`settingsOpen` state）から開くモーダルとして実装しており、タブ切り替えとは
独立した表示（下部固定タブバーとは別のUI階層）。`api/auth.ts`の
`fetchNotificationSettings`/`putNotificationSettings`/`deleteNotificationSettings`を使い、
登録（PUT）はバックエンド側で実際にテスト送信されるため、フォーム側は成功/失敗メッセージを
そのまま表示するだけでよい（クライアント側でのURL妥当性検証はプレフィックスチェックのみ）。

## index.css の CSS カスケードレイヤーに関する注意
`*, *::before, *::after` の余白リセットは必ず `@layer base` の中に書くこと。
`@layer` の外（unlayered）に書くと、CSS カスケードレイヤーの仕様上どんな `@layer utilities`
（Tailwind の padding/margin ユーティリティ含む）よりも優先されてしまい、
`px-*`/`py-*`/`pb-*` 等のユーティリティが軒並み無効化される（過去に実際に発生したバグ）。

## 実行環境表示の日本語化（HealthStatus.tsx）
`/health` の `environment` フィールド（`production`/`development`）はそのまま表示せず、
`ENVIRONMENT_LABELS` で「本番環境」/「開発環境」に変換してから表示する。

## APIクライアントの分割構成（dashboard/src/api/）
`client.ts`（元は451行の単一ファイル）は、ドメインごとに `shared.ts`/`kev.ts`/`osv.ts`/
`jvn.ts`/`depscan.ts`/`depsops.ts`/`codescan.ts`/`crawlerLogs.ts`/`auth.ts` に分割し、
`client.ts`自体はバーレル（re-export）として残している。既存の`import { xxx } from
'../api/client'`は全て動き続ける。新しいAPI呼び出し関数を追加する場合は対応ドメインの
ファイルに追加すること。
