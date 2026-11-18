import type { OperatingStatus } from '../../api/client'

// 依存パッケージの画面の、文言・既定値（画面は、これを読んで描くだけ）
export const PER_PAGE = 20

// 絞り込みに使うエコシステム（DEPSCAN が対応するもののうち、自作アプリで使うもの）
export const ECOSYSTEMS = ['npm', 'PyPI', 'Pub']

export const INPUT_CLS =
  'rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-violet-500'

export const TH = 'text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3'

// 表示に使う条件。変わるたびに取り直す（入力欄の文字は「検索」で確定するまで含めない）
export interface Filters {
  repo: string | null
  operating: OperatingStatus
  vulnerableOnly: boolean
  ecosystem: string | null
  packageName: string
  version: string
  page: number
}

// 初期表示は運用中のアプリすべて。何も入力しなくても、使っている依存を一覧できる
export const INITIAL_FILTERS: Filters = {
  repo: null, operating: 'active', vulnerableOnly: false, ecosystem: null,
  packageName: '', version: '', page: 1,
}

export const DEPENDENCIES_TEXT = {
  label: '依存パッケージ',
  intro:
    '各アプリが使っている依存パッケージの一覧です。左でアプリを選ぶと、そのアプリが使っている依存を見られます。 '
    + '新しい脆弱性が公表されたときは、パッケージ名で検索して、影響を受けるアプリと版を確認できます。',
  packageName: 'パッケージ名（部分一致）',
  packagePlaceholder: '例: undici',
  version: 'バージョン（完全一致）',
  versionPlaceholder: '例: 8.11.2',
  ecosystem: 'エコシステム',
  all: 'すべて',
  search: '検索',
  vulnerableOnly: '脆弱性ありのみ',
  failed: '取得に失敗しました。時間をおいて再度お試しください',
  emptyVulnerable: '未解決の検知がある依存パッケージはありません',
  empty: '該当する依存パッケージはありません',
  tableLabel: '依存パッケージ一覧',
  columns: {
    app: 'アプリ', package: 'パッケージ', version: 'バージョン', vulnerability: '脆弱性', lockfile: 'ロックファイル',
  },
  noFinding: '検知なし',
  openFindings: (count: number) => `未解決 ${count} 件`,
  repoTotalTitle: '使っている依存の数',
  repoVulnerableTitle: '未解決の検知がある依存の数',
} as const
