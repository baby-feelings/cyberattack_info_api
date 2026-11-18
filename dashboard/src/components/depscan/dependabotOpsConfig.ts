// Dependabot 運用状況の画面の、文言・既定値（画面は、これを読んで描くだけ）
export const PER_PAGE = 20

export type ActionFilter = 'ALL' | 'merged' | 'flagged'

export const ACTIONS: { key: ActionFilter; label: string }[] = [
  { key: 'ALL', label: 'すべて' },
  { key: 'merged', label: '自動マージ' },
  { key: 'flagged', label: '要確認' },
]

export const TH = 'text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3'

export const DEPSOPS_TEXT = {
  label: 'Dependabot 運用状況',
  title: 'Dependabot 運用状況（DEPSOPS）',
  actionGroup: '判定フィルター',
  empty: '該当する PR はありません',
  tableLabel: 'Dependabot PR 判定履歴',
  columns: {
    repo: 'リポジトリ', score: '互換性スコア', pr: 'PR', action: '判定', kind: '種別', date: '日時',
  },
  merged: '自動マージ',
  flagged: '要確認',
  unknown: '不明',
  securityUpdate: 'セキュリティ更新',
  versionUpdate: 'バージョン更新',
  scoreAlt: 'Dependabot compatibility score',
} as const
