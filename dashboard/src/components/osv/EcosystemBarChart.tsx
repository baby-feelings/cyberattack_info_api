import { BarChart2 } from 'lucide-react'
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip as ReTooltip, XAxis, YAxis } from 'recharts'
import { type OsvStatsResponse } from '../../api/client'
import { ChartCard } from '../shared/VulnPanelParts'

// エコシステム別グラフの色（順番で割り当て）
const ECO_CHART_COLORS = [
  '#7c3aed', '#0ea5e9', '#22d3ee', '#f59e0b',
  '#f43f5e', '#8b5cf6', '#f97316', '#6366f1', '#10b981', '#14b8a6',
]

// ツールチップの表示値フォーマッタ（テストで直接検証できるよう名前付き関数として切り出す）
export function formatEcosystemTooltipValue(value: unknown): [string, string] {
  return [String(value) + ' 件', '件数']
}

// エコシステム別棒グラフ（エコシステムごとに色分け。汎用 MonthlyBarChart とは形が異なるため専用実装）
export function EcosystemBarChart({ stats, loading }: { stats: OsvStatsResponse | null; loading: boolean }) {
  // 上位 8 エコシステムのみ表示
  const data = (stats?.ecosystems ?? []).slice(0, 8)

  return (
    <ChartCard
      icon={<BarChart2 size={13} className="text-slate-400" />}
      title="エコシステム別件数"
      loading={loading}
      isEmpty={data.length === 0}
      height={160}
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
          <XAxis
            dataKey="ecosystem"
            tick={{ fill: '#475569', fontSize: 10 }}
            tickLine={false}
            axisLine={false}
          />
          <YAxis
            tick={{ fill: '#475569', fontSize: 10 }}
            tickLine={false}
            axisLine={false}
            allowDecimals={false}
          />
          <ReTooltip
            contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
            formatter={formatEcosystemTooltipValue}
          />
          <Bar dataKey="count" radius={[3, 3, 0, 0]}>
            {data.map((_entry, index) => (
              <Cell
                key={`cell-${index}`}
                fill={ECO_CHART_COLORS[index % ECO_CHART_COLORS.length]}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}
