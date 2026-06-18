import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import { TrendingUp } from 'lucide-react'
import type { MonthlyStat } from '../api/client'

interface Props {
  data: MonthlyStat[]
  loading: boolean
}

function CustomTooltip({ active, payload, label }: {
  active?: boolean
  payload?: { value: number }[]
  label?: string
}) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl px-3 py-2 text-sm shadow-xl">
      <p className="text-slate-400 mb-0.5">{label}</p>
      <p className="text-violet-300 font-bold text-base">{payload[0].value} 件</p>
    </div>
  )
}

export function MonthlyTrend({ data, loading }: Props) {
  return (
    <div className="h-full rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg flex flex-col gap-4">

      <div className="flex items-center gap-2">
        <TrendingUp size={15} className="text-slate-400" />
        <span className="text-sm font-semibold text-slate-400 uppercase tracking-wider">月別 CVE 追加数トレンド</span>
      </div>

      <div className="h-[220px]">
        {loading ? (
          <div className="h-full flex items-center justify-center">
            <div className="flex flex-col items-center gap-2">
              <div className="w-8 h-8 border-2 border-violet-500/30 border-t-violet-500 rounded-full animate-spin" />
              <p className="text-xs text-slate-600">読み込み中...</p>
            </div>
          </div>
        ) : data.length === 0 ? (
          <div className="h-full flex items-center justify-center">
            <p className="text-xs text-slate-600">データがありません</p>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 4, right: 4, left: -28, bottom: 0 }}>
              <defs>
                <linearGradient id="grad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#7c3aed" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#7c3aed" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis
                dataKey="year_month"
                tick={{ fill: '#475569', fontSize: 12 }}
                tickLine={false}
                axisLine={false}
                interval="preserveStartEnd"
              />
              <YAxis
                tick={{ fill: '#475569', fontSize: 12 }}
                tickLine={false}
                axisLine={false}
                allowDecimals={false}
              />
              <Tooltip content={<CustomTooltip />} cursor={{ stroke: '#334155', strokeWidth: 1 }} />
              <Area
                type="monotone"
                dataKey="count"
                stroke="#7c3aed"
                strokeWidth={2}
                fill="url(#grad)"
                dot={false}
                activeDot={{ r: 4, fill: '#7c3aed', stroke: '#0a0e1a', strokeWidth: 2 }}
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  )
}
