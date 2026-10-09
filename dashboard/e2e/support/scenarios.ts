// E2Eシナリオカタログ: ダッシュボードの「画面・機能・状態遷移」を網羅的に列挙した一覧。
//
// 各テストは `scenario(id, ...)`（e2e/support/test.ts）で必ずこのカタログのIDに紐づける。
// シナリオ網羅率 = 「合格したシナリオ数 ÷ カタログ総数」であり、カスタムレポーター
// （e2e/reporters/scenario-coverage-reporter.ts）がHTMLに出力し、90%未満なら失敗にする。
// 新しい画面・機能を追加したら、まずここへ行を追加し、対応するテストを書くこと。

export const SCENARIOS = [
  // ── アプリ全体（ヘッダー・タブ・フッター・メニュー） ─────────────────
  { id: 'APP-01', area: 'アプリ全体', title: '初期表示でヘッダー・KEVタブ・フッターが表示される' },
  { id: 'APP-02', area: 'アプリ全体', title: '5つのタブが切り替わり対応するタブパネルが表示される' },
  { id: 'APP-03', area: 'アプリ全体', title: 'ハンバーガーメニューの開閉（外側クリック・Escapeで閉じる）' },
  { id: 'APP-04', area: 'アプリ全体', title: 'OAuthコールバック（?depscan_code）でDEPSCANタブが自動選択されログインされる' },
  { id: 'APP-05', area: 'アプリ全体', title: 'OAuth交換コードが無効ならログイン画面のまま' },
  { id: 'APP-06', area: 'アプリ全体', title: 'アクセシビリティツリー（ARIAスナップショット）がタブUIの意味構造を表す' },
  { id: 'APP-07', area: 'アプリ全体', title: 'モバイル幅でもタブバーとコンテンツが操作できる' },

  // ── サーバー稼働状況 ───────────────────────────────────────────────
  { id: 'HLT-01', area: 'サーバー稼働状況', title: '正常時に OK・DB接続正常・本番環境が表示される' },
  { id: 'HLT-02', area: 'サーバー稼働状況', title: 'degraded かつ DB 未接続のときエラー表示になる' },
  { id: 'HLT-03', area: 'サーバー稼働状況', title: 'APIが到達不能のとき UNREACHABLE が表示される' },
  { id: 'HLT-04', area: 'サーバー稼働状況', title: '再確認ボタンで /health を再取得し状態が更新される' },
  { id: 'HLT-05', area: 'サーバー稼働状況', title: '開発環境の表記（development）が日本語化される' },

  // ── KEV ───────────────────────────────────────────────────────────
  { id: 'KEV-01', area: 'KEV', title: '一覧・件数サマリー・グラフが表示される' },
  { id: 'KEV-02', area: 'KEV', title: '行クリックで詳細（説明・推奨対処・EPSS）が展開/折りたたみされる' },
  { id: 'KEV-03', area: 'KEV', title: 'キーワード検索で絞り込まれ、クリアで元に戻る' },
  { id: 'KEV-04', area: 'KEV', title: 'ページ送り（次へ/前へ）と境界でのボタン無効化' },
  { id: 'KEV-05', area: 'KEV', title: '該当なしのとき空状態メッセージが表示される' },
  { id: 'KEV-06', area: 'KEV', title: '再読み込みボタンで一覧と統計が再取得される' },
  { id: 'KEV-07', area: 'KEV', title: 'EPSS未取得は「—」、CVE IDはNVDへの外部リンクになる' },
  { id: 'KEV-08', area: 'KEV', title: 'APIエラー時もクラッシュせずデータなし状態になる' },
  { id: 'KEV-09', area: 'KEV', title: 'リクエストに公開用 X-API-KEY ヘッダーが付与される' },
  { id: 'KEV-10', area: 'KEV', title: 'ページ送りの最初/最後ボタンとページ番号の直接入力' },
  { id: 'KEV-11', area: 'KEV', title: 'スマホ幅でもページ送りが画面内に収まり横スクロールしない' },

  // ── OSV ───────────────────────────────────────────────────────────
  { id: 'OSV-01', area: 'OSV', title: '一覧・CRIT/HIGH件数・グラフが表示される' },
  { id: 'OSV-02', area: 'OSV', title: 'エコシステムフィルターでリクエストと一覧が絞り込まれる' },
  { id: 'OSV-03', area: 'OSV', title: '深刻度フィルターで絞り込まれ、ALLで解除される' },
  { id: 'OSV-04', area: 'OSV', title: 'キーワード検索とクリア' },
  { id: 'OSV-05', area: 'OSV', title: 'ソートを更新日/CVSSで切り替えられる' },
  { id: 'OSV-06', area: 'OSV', title: '行クリックで詳細（修正版・エイリアス・参考リンク）が展開される' },
  { id: 'OSV-07', area: 'OSV', title: 'ページ送り' },
  { id: 'OSV-08', area: 'OSV', title: '該当なしのとき空状態メッセージが表示される' },
  { id: 'OSV-09', area: 'OSV', title: 'フィルター変更時にページが1に戻る' },
  { id: 'OSV-10', area: 'OSV', title: 'ページ送りの最初/最後ボタンとページ番号の直接入力' },

  // ── JVN ───────────────────────────────────────────────────────────
  { id: 'JVN-01', area: 'JVN', title: '一覧・HIGH/MED件数・グラフが表示される' },
  { id: 'JVN-02', area: 'JVN', title: '深刻度フィルターで絞り込まれる' },
  { id: 'JVN-03', area: 'JVN', title: 'キーワード検索とクリア' },
  { id: 'JVN-04', area: 'JVN', title: 'ソートを更新日/CVSSで切り替えられる' },
  { id: 'JVN-05', area: 'JVN', title: '行クリックで詳細（概要・CVSSベクター・影響製品）が展開される' },
  { id: 'JVN-06', area: 'JVN', title: 'ページ送り' },
  { id: 'JVN-07', area: 'JVN', title: '該当なしのとき空状態メッセージが表示される' },
  { id: 'JVN-08', area: 'JVN', title: '再読み込みボタンで再取得される' },
  { id: 'JVN-09', area: 'JVN', title: 'ページ送りの最初/最後ボタンとページ番号の直接入力' },

  // ── DEPSCAN ───────────────────────────────────────────────────────
  { id: 'DEP-01', area: 'DEPSCAN', title: '未ログイン時はGitHubログイン案内とログインリンクが表示される' },
  { id: 'DEP-02', area: 'DEPSCAN', title: 'ログイン済みでスキャン中表示から完了後にパネルへ遷移する' },
  { id: 'DEP-03', area: 'DEPSCAN', title: 'パッケージ単位に集約した一覧と件数サマリーが表示される' },
  { id: 'DEP-04', area: 'DEPSCAN', title: '行クリックで個別CVE・ロックファイル・修正版が展開される' },
  { id: 'DEP-05', area: 'DEPSCAN', title: '深刻度フィルターでリクエストと一覧が絞り込まれる' },
  { id: 'DEP-06', area: 'DEPSCAN', title: '「解決済みを含む」切替で解決済みが表示される' },
  { id: 'DEP-07', area: 'DEPSCAN', title: '複数オーナーのときオーナーフィルターが表示され絞り込める' },
  { id: 'DEP-08', area: 'DEPSCAN', title: 'Dependabot運用状況モーダルを開き一覧・フィルターを操作できる' },
  { id: 'DEP-09', area: 'DEPSCAN', title: 'モーダルを閉じるボタン/Escapeで閉じられる' },
  { id: 'DEP-10', area: 'DEPSCAN', title: 'ログアウトは確認ダイアログを経て未ログインに戻る（キャンセルで維持）' },
  { id: 'DEP-11', area: 'DEPSCAN', title: 'スキャンエラー状態のときエラーバナーが表示される' },
  { id: 'DEP-12', area: 'DEPSCAN', title: 'セッション失効（401）で自動的にログアウトされる' },
  { id: 'DEP-13', area: 'DEPSCAN', title: '新しいクロールを検知すると更新バナーが表示され更新できる' },
  { id: 'DEP-14', area: 'DEPSCAN', title: '該当なしのとき空状態メッセージが表示される' },
  { id: 'DEP-15', area: 'DEPSCAN', title: 'リクエストにBearerトークンが付与される（X-API-KEYではない）' },
  { id: 'DEP-16', area: 'DEPSCAN', title: 'モーダルのページ送りと該当なし状態' },
  { id: 'DEP-17', area: 'DEPSCAN', title: 'モーダルのページ送りの最初/最後ボタンとページ番号の直接入力' },

  // ── CODESCAN ──────────────────────────────────────────────────────
  { id: 'COD-01', area: 'CODESCAN', title: '未ログイン時はGitHubログイン案内が表示される' },
  { id: 'COD-02', area: 'CODESCAN', title: 'ログイン済みで一覧・統計・注記が表示される' },
  { id: 'COD-03', area: 'CODESCAN', title: '重要度フィルター（重大/警告/情報）で絞り込まれる' },
  { id: 'COD-04', area: 'CODESCAN', title: '状態フィルター（未解決/解決済み/全件）が切り替わる' },
  { id: 'COD-05', area: 'CODESCAN', title: '行クリックで詳細（メッセージ・スニペット・CWE・OWASP）が展開される' },
  { id: 'COD-06', area: 'CODESCAN', title: '該当なしのとき空状態メッセージが表示される' },
  { id: 'COD-07', area: 'CODESCAN', title: 'DEPSCANとCODESCANでログインセッションが共有される' },
  { id: 'COD-08', area: 'CODESCAN', title: 'ログアウトで未ログインに戻る' },
  { id: 'COD-09', area: 'CODESCAN', title: 'ページ送り' },
  { id: 'COD-10', area: 'CODESCAN', title: 'CVSS 7.0以上のバッジ強調・未算出表示・ツールバッジ' },
  { id: 'COD-11', area: 'CODESCAN', title: 'ページ送りの最初/最後ボタンとページ番号の直接入力' },

  // ── 設定（Slack通知登録） ─────────────────────────────────────────
  { id: 'SET-01', area: '設定', title: 'メニュー→設定で開き、未ログイン時はログイン案内が表示される' },
  { id: 'SET-02', area: '設定', title: '閉じるボタン・背景クリックで閉じられる' },
  { id: 'SET-03', area: '設定', title: 'ログイン済みで既存の登録URLが読み込まれる' },
  { id: 'SET-04', area: '設定', title: 'Webhook URLを保存すると成功メッセージが表示される' },
  { id: 'SET-05', area: '設定', title: '保存失敗時にサーバーのエラー詳細が表示される' },
  { id: 'SET-06', area: '設定', title: '登録解除でURLがクリアされる' },
  { id: 'SET-07', area: '設定', title: '入力が空の間は保存ボタンが無効' },
  { id: 'SET-08', area: '設定', title: '設定の取得失敗時にエラーメッセージが表示される' },
  { id: 'SET-09', area: '設定', title: '設定画面からのログアウト' },
  { id: 'SET-10', area: '設定', title: 'MCPトークンを発行すると登録コマンドと有効期限が表示される' },
  { id: 'SET-11', area: '設定', title: 'MCPトークンの発行に失敗するとエラーが表示される' },
] as const

export type ScenarioId = (typeof SCENARIOS)[number]['id']
