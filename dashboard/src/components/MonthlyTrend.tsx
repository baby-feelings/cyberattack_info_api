// 月別トレンドグラフ（面グラフ）
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts'
import { TrendingUp } from 'lucide-react'
import type { MonthlyStat } from '../api/client'

interface Props {
  data: MonthlyStat[]
  loading: boolean
}

// カスタムツールチップ
function CustomTooltip({ active, payload, label }: { active?: boolean; payload?: { value: number }[]; label?: string }) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm shadow-lg">
      <p className="text-slate-300">{label}</p>
      <p className="text-violet-400 font-semibold">{payload[0].value} 件</p>
    </div>
  )
}

export function MonthlyTrend({ data, loading }: Props) {
  return (
    <div className="bg-slate-800 rounded-2xl p-6 border border-slate-700">
      <div className="flex items-center gap-2 mb-5">
        <TrendingUp size={18} className="text-slate-400" />
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">月別 CVE 追加数トレンド</h2>
      </div>

      {loading ? (
        <div className="h-48 flex items-center justify-center text-slate-500">読み込み中...</div>
      ) : data.length === 0 ? (
        <div className="h-48 flex items-center justify-center text-slate-500">データなし</div>
      ) : (
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={data} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="trendGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#7c3aed" stopOpacity={0.4} />
                <stop offset="95%" stopColor="#7c3aed" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis
              dataKey="year_month"
              tick={{ fill: '#94a3b8', fontSize: 11 }}
              tickLine={false}
              axisLine={false}
            />
            <YAxis
              tick={{ fill: '#94a3b8', fontSize: 11 }}
              tickLine={false}
              axisLine={false}
              allowDecimals={false}
            />
            <Tooltip content={<CustomTooltip />} />
            <Area
              type="monotone"
              dataKey="count"
              stroke="#7c3aed"
              strokeWidth={2}
              fill="url(#trendGradient)"
              dot={{ fill: '#7c3aed', r: 3 }}
              activeDot={{ r: 5 }}
            />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}
