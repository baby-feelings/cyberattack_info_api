import type { OperatingStatus, RuntimeState } from '../../api/client'

// 言語・実行環境の画面の、文言・色・既定値（画面は、これを読んで描くだけ）
export const INPUT_CLS =
  'rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-violet-500'

export const TH = 'text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3'

// 絞り込みに使う言語（バックエンドの識別子と表示名）
export const RUNTIME_OPTIONS = [
  { value: 'python', label: 'Python' },
  { value: 'nodejs', label: 'Node.js' },
  { value: 'flutter', label: 'Flutter' },
  { value: 'dart', label: 'Dart' },
]

// 状態の表示（文言と色）。対応が急ぐものほど目立たせる
export const STATE_BADGE: Record<RuntimeState, { label: string; cls: string }> = {
  eol: { label: 'サポート終了', cls: 'bg-red-500/15 text-red-400 border-red-500/30' },
  eol_soon: { label: '期限間近', cls: 'bg-orange-500/15 text-orange-400 border-orange-500/30' },
  update_available: { label: '更新あり', cls: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30' },
  latest: { label: '最新', cls: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' },
  reference: { label: '参考（下限の指定）', cls: 'bg-slate-700/40 text-slate-400 border-slate-600' },
  unknown: { label: '不明', cls: 'bg-slate-700/40 text-slate-400 border-slate-600' },
}

// 表示に使う条件。変わるたびに取り直す
export interface Filters {
  repo: string | null
  operating: OperatingStatus
  needsActionOnly: boolean
  runtime: string | null
}

// 初期表示は運用中のアプリすべて。何も操作しなくても、使っている言語・実行環境を一覧できる
export const INITIAL_FILTERS: Filters = {
  repo: null, operating: 'active', needsActionOnly: false, runtime: null,
}

// 公開から、この日数たつまで推奨にしない（バックエンドの RECOMMEND_MIN_AGE_DAYS と同じ値）
export const RECOMMEND_MIN_AGE_DAYS = 180

// 画面の文言
export const RUNTIMES_TEXT = {
  label: '言語・実行環境',
  intro:
    '各アプリが使っている Python・Node.js・Flutter・Dart の版と、サポート期限です。 '
    + 'サポートが終わった版には、セキュリティ修正が提供されません。左でアプリを選ぶと、そのアプリの設定を見られます。',
  language: '言語',
  all: 'すべて',
  needsActionOnly: '更新が必要なものだけ',
  failed: '取得に失敗しました。時間をおいて再度お試しください',
  emptyNeedsAction: '更新が必要な言語・実行環境はありません',
  empty: '該当する言語・実行環境はありません',
  tableLabel: '言語・実行環境一覧',
  columns: {
    app: 'アプリ', runtime: '言語', version: '使っている版', state: '状態',
    recommended: '推奨の版', eol: 'サポート終了', source: '設定ファイル',
  },
} as const
