// 概要タブの設定。指標の一覧・文言・色・移動先を、このファイルの1か所に置く（画面・クラスには直書きしない）。
import type { TabKey } from '../layout/tabs'

// 移動先（タブと、あれば小タブ）
export interface NavTarget {
  tab: TabKey
  subTab?: string
}

export type OverviewGroup = 'dependency' | 'code' | 'ops'

// count=件数（0が正常）/ percent=達成率（100が正常）
export type MetricUnit = 'count' | 'percent'

export interface MetricDefinition {
  id: string
  label: string
  group: OverviewGroup
  unit: MetricUnit
  target: NavTarget
}

// 並び順どおりに表示する
export const OVERVIEW_METRICS: MetricDefinition[] = [
  { id: 'dep-open', label: '未解決の脆弱性', group: 'dependency', unit: 'count', target: { tab: 'dependencies', subTab: 'scan' } },
  { id: 'dep-overdue', label: '対応期限を超過', group: 'dependency', unit: 'count', target: { tab: 'dependencies', subTab: 'sla' } },
  { id: 'dep-eol', label: '言語のサポート期限が間近・終了', group: 'dependency', unit: 'count', target: { tab: 'dependencies', subTab: 'runtimes' } },
  { id: 'dep-alerts', label: 'Dependabot のアラート', group: 'dependency', unit: 'count', target: { tab: 'dependencies', subTab: 'alerts' } },
  { id: 'code-open', label: '未解決の指摘', group: 'code', unit: 'count', target: { tab: 'code', subTab: 'scan' } },
  { id: 'code-alerts', label: 'コード・シークレットのアラート', group: 'code', unit: 'count', target: { tab: 'code', subTab: 'alerts' } },
  { id: 'code-audit', label: 'リポジトリ設定の達成率', group: 'code', unit: 'percent', target: { tab: 'code', subTab: 'audit' } },
  { id: 'ops-sites', label: '問題のある公開サイト', group: 'ops', unit: 'count', target: { tab: 'ops' } },
]

export const OVERVIEW_GROUP_LABEL: Record<OverviewGroup, string> = {
  dependency: '依存ライブラリ',
  code: 'コードと設定',
  ops: '運用',
}

// 達成率が、この値以上なら正常
export const PERCENT_OK_AT = 100

// 概要の対象。運用停止中のアプリは数えない
export const OVERVIEW_OPERATING = 'active' as const

// 「サポート期限が間近・終了」として数える、言語の状態
export const OVERVIEW_EOL_STATES: readonly string[] = ['eol', 'eol_soon']

export type MetricState = 'ok' | 'warn' | 'unknown'

export const METRIC_STATE_CLASS: Record<MetricState, { value: string; border: string }> = {
  ok: { value: 'text-emerald-400', border: 'border-emerald-900/50' },
  warn: { value: 'text-amber-400', border: 'border-amber-800/60' },
  unknown: { value: 'text-slate-500', border: 'border-slate-800' },
}

export const OVERVIEW_TEXT = {
  heading: '概要 — いま対応が必要なもの',
  reload: '概要を再読み込み',
  subtitle: '運用中のアプリだけを数えています。押すと、詳細の画面へ移ります',
  loginDescription: 'ログインすると、あなたのリポジトリの、対応が必要な件数をまとめて確認できます',
  unknown: '不明',
  unitCount: '件',
  unitPercent: '%',
  loading: '集計中',
} as const
