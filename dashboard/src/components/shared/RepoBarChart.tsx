import { BarChart2 } from 'lucide-react'
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip as ReTooltip, XAxis, YAxis } from 'recharts'
import { ChartCard } from './VulnPanelParts'

// 棒の色の既定のパレット（画面ごとに差し替えられる）
export const DEFAULT_REPO_CHART_COLORS = [
  '#7c3aed', '#0ea5e9', '#22d3ee', '#f59e0b',
  '#f43f5e', '#8b5cf6', '#f97316', '#6366f1',
]
// 例外にした件数の積み上げの色
const EXCEPTED_COLOR = '#475569'
// 表示するリポジトリの数（件数の多い順）
const TOP_REPOS = 8

// 1リポジトリぶんの値。excepted があれば、件数に積み上げて表示する
export interface RepoBarDatum {
  repo_full_name: string
  count: number
  excepted_count?: number
}

// ツールチップの表示値フォーマッタ（テストで直接検証できるよう名前付き関数として切り出す）
export function formatRepoTooltipValue(value: unknown, name: unknown): [string, string] {
  return [String(value) + ' 件', String(name)]
}

// リポジトリ別件数の棒グラフ（上位8件）。DEPSCAN・CODESCAN・DEPSOPS の3画面で共通。
// 画面ごとの違い（題名・補足・色・系列名・例外の積み上げ）は、props で受け取る
export function RepoBarChart({
  data: source, loading, title, description, palette = DEFAULT_REPO_CHART_COLORS,
  countName = '件数', exceptedName,
}: {
  data: RepoBarDatum[]
  loading: boolean
  title: string
  description?: string
  palette?: readonly string[]
  // 件数の系列名（ツールチップに出る）
  countName?: string
  // 指定すると、例外にした件数を積み上げて表示する（その系列名）
  exceptedName?: string
}) {
  const data = source.slice(0, TOP_REPOS).map(r => ({
    // "owner/repo" だとラベルが長くなるため repo 名のみ表示
    name: r.repo_full_name.split('/')[1] ?? r.repo_full_name,
    count: r.count,
    excepted: r.excepted_count ?? 0,
  }))
  const stacked = exceptedName !== undefined

  return (
    <ChartCard
      icon={<BarChart2 size={13} className="text-slate-400" />}
      title={title}
      description={description}
      loading={loading}
      isEmpty={data.length === 0}
      height={160}
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
          <XAxis
            dataKey="name"
            tick={{ fill: '#475569', fontSize: 9 }}
            tickLine={false}
            axisLine={false}
            interval={0}
            angle={-30}
            textAnchor="end"
            height={40}
          />
          <YAxis tick={{ fill: '#475569', fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false} />
          <ReTooltip
            contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
            formatter={formatRepoTooltipValue}
          />
          <Bar dataKey="count" name={countName} stackId={stacked ? 'repo' : undefined} radius={stacked ? undefined : [3, 3, 0, 0]}>
            {data.map((_entry, index) => (
              <Cell key={`cell-${index}`} fill={palette[index % palette.length]} />
            ))}
          </Bar>
          {stacked && (
            <Bar dataKey="excepted" name={exceptedName} stackId="repo" fill={EXCEPTED_COLOR} radius={[3, 3, 0, 0]} />
          )}
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
