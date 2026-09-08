import { BarChart2 } from 'lucide-react'
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip as ReTooltip, XAxis, YAxis } from 'recharts'
import { ChartCard } from '../shared/VulnPanelParts'
import type { RepoOpsStat } from './depsopsGrouping'

const CHART_COLORS = [
  '#f59e0b', '#f97316', '#f43f5e', '#8b5cf6',
  '#7c3aed', '#0ea5e9', '#22d3ee', '#6366f1',
]

// ツールチップの表示値フォーマッタ（テストで直接検証できるよう名前付き関数として切り出す）
export function formatDepsOpsRepoTooltipValue(value: unknown): [string, string] {
  return [String(value) + ' 件', '件数']
}

// リポジトリ別「要確認」PR件数の棒グラフ（上位8件。同一PRの重複日数分は
// computeUnresolvedRepoStats 側で最新状態のみに集約済みのデータを受け取る）
export function DepsOpsRepoBarChart({ stats, loading }: { stats: RepoOpsStat[]; loading: boolean }) {
  const data = stats.slice(0, 8).map(s => ({
    // "owner/repo" だとラベルが長くなるため repo 名のみ表示
    name: s.repo_full_name.split('/')[1] ?? s.repo_full_name,
    count: s.count,
  }))

  return (
    <ChartCard
      icon={<BarChart2 size={13} className="text-slate-400" />}
      title="リポジトリ別件数（未解決）"
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
          <YAxis
            tick={{ fill: '#475569', fontSize: 10 }}
            tickLine={false}
            axisLine={false}
            allowDecimals={false}
          />
          <ReTooltip
            contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
            formatter={formatDepsOpsRepoTooltipValue}
          />
          <Bar dataKey="count" radius={[3, 3, 0, 0]}>
            {data.map((_entry, index) => (
              <Cell key={`cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
