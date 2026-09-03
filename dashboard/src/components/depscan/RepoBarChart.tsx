import { BarChart2 } from 'lucide-react'
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip as ReTooltip, XAxis, YAxis } from 'recharts'
import { ChartCard } from '../shared/VulnPanelParts'
import type { DepscanStatsResponse } from '../../api/client'

const REPO_CHART_COLORS = [
  '#7c3aed', '#0ea5e9', '#22d3ee', '#f59e0b',
  '#f43f5e', '#8b5cf6', '#f97316', '#6366f1',
]

// リポジトリ別件数の棒グラフ（上位8件）
export function RepoBarChart({ stats, loading }: { stats: DepscanStatsResponse | null; loading: boolean }) {
  const data = (stats?.repos ?? []).slice(0, 8).map(r => ({
    // "owner/repo" だとラベルが長くなるため repo 名のみ表示
    name: r.repo_full_name.split('/')[1] ?? r.repo_full_name,
    count: r.count,
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
            formatter={(value) => [String(value) + ' 件', '件数']}
          />
          <Bar dataKey="count" radius={[3, 3, 0, 0]}>
            {data.map((_entry, index) => (
              <Cell key={`cell-${index}`} fill={REPO_CHART_COLORS[index % REPO_CHART_COLORS.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
