// DEPSCAN（検知）の画面の、文言・既定値（画面は、これを読んで描くだけ）
export const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export const TH = 'text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3'

export const DEPSCAN_TEXT = {
  newData: '新しいデータがあります',
  refresh: '更新',
  title: '自作アプリの依存ライブラリ脆弱性（未解決）',
  reload: '再読み込み',
  charts: 'グラフ（重要度別・リポジトリ別）',
  ownerGroup: 'オーナーフィルター',
  showResolved: '解決済みを含む',
  actionCriteria: 'CRITICAL・HIGH',
  empty: '該当する依存ライブラリ脆弱性はありません',
  tableLabel: '依存ライブラリ脆弱性一覧',
  columns: {
    severity: '深刻度', repo: 'リポジトリ', package: 'パッケージ', fixed: '修正版',
    reachability: '到達可能性', detected: '検知日',
  },
} as const
