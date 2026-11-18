// OSV の画面の、文言・色・既定値（画面は、これを読んで描くだけ）

// 深刻度バッジのスタイル
export const SEVERITY_CLS: Record<string, string> = {
  CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
  HIGH:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
  MEDIUM:   'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  LOW:      'bg-blue-500/15 text-blue-400 border-blue-500/30',
}

// 重要度別グラフの色
export const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#3b82f6',
  'N/A':    '#475569',
}

export const ECOSYSTEMS = ['ALL', 'PyPI', 'npm', 'Go', 'Maven', 'RubyGems', 'NuGet', 'crates.io', 'Packagist', 'Hex', 'Pub']
export const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export const TH = 'text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3'

export const OSV_TEXT = {
  title: (period: number) => `OSV 脆弱性（直近 ${period} 日）`,
  reload: '再読み込み',
  charts: 'グラフ（重要度別・エコシステム別・月別）',
  monthlyTitle: '月別 OSV 更新トレンド（6ヶ月）',
  updatedInPeriod: (period: number) => `件が直近${period}日に更新`,
  criticalHigh: '件は CRITICAL・HIGH',
  ecosystemGroup: 'エコシステムフィルター',
  searchPlaceholder: 'OSV ID・パッケージ名・概要',
  empty: '該当する OSV 脆弱性はありません',
  tableLabel: 'OSV 脆弱性一覧',
  columns: {
    severity: '深刻度', osvId: 'OSV ID', ecosystem: 'エコシステム', package: 'パッケージ',
    summary: '概要', modified: '更新日',
  },
} as const
