// 対応状況（SLA）画面の文言・表の見出し・しきい値。画面（SlaPanel・SlaSections）には、文言を直書きしない。
export const SLA_TEXT = {
  label: '対応状況',
  description:
    '検知から解決までの日数と、重要度ごとの対応期限（SLA）を超えている検知です。'
    + 'LOW・重要度不明は期限がありません。CISA KEV に掲載された検知は、重要度によらず期限が短くなります。',
  loadFailed: '取得に失敗しました。時間をおいて再度お試しください',
  summaryLabel: '対応状況の概要',
  noMttr: '—',
  unit: { count: '件', days: '日' },
  tile: {
    overdue: '期限超過',
    open: '未解決（期限あり）',
    resolved: (days: number) => `直近${days}日の解決`,
    mttr: '平均対応日数（MTTR）',
    mttrHint: '検知から解決までの平均日数',
  },
  policy: {
    label: '対応期限',
    prefix: '対応期限:',
    kev: 'KEV掲載',
    excluded: (n: number) => `（除外中: ${n}件）`,
  },
  overdue: {
    tableLabel: '期限超過の検知一覧',
    empty: '期限を超えている検知はありません',
    unknownSeverity: '不明',
    maliciousTitle: '悪意あるパッケージ',
    kev: 'KEV',
    daysOver: (n: number) => `${n} 日超過`,
    columns: { severity: '重要度', repo: 'リポジトリ', package: 'パッケージ', deadline: '期限', over: '超過' },
  },
  bySeverity: {
    title: '重要度別',
    tableLabel: '重要度別の対応状況',
    columns: { severity: '重要度', deadline: '期限', open: '未解決', over: '超過', mttr: '平均対応' },
  },
  byRepo: {
    title: 'リポジトリ別',
    tableLabel: 'リポジトリ別の対応状況',
    columns: { repo: 'リポジトリ', open: '未解決', over: '超過', mttr: '平均対応' },
  },
} as const

// 取得中の表の骨組みの列幅
export const SLA_SKELETON_COLUMNS = ['w-40', 'w-24', 'w-24', 'w-32', 'flex-1']
// 表の見出しセルの共通の見た目
export const SLA_TH = 'text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3'
