// ベンダー別脆弱性ランキング（Top 10 横棒グラフ）
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell,
} from 'recharts'
import { Trophy } from 'lucide-react'
import type { VendorStat } from '../api/client'

interface Props {
  data: VendorStat[]
  loading: boolean
}

// 順位に応じて色を変える
const BAR_COLORS = ['#f59e0b', '#94a3b8', '#cd7c2f', '#7c3aed', '#7c3aed', '#7c3aed', '#7c3aed', '#7c3aed', '#7c3aed', '#7c3aed']

function CustomTooltip({ active, payload }: { active?: boolean; payload?: { payload: VendorStat; value: number }[] }) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm shadow-lg">
      <p className="text-slate-200 font-semibold">{payload[0].payload.vendor_project}</p>
      <p className="text-amber-400">{payload[0].value} 件</p>
    </div>
  )
}

export function VendorRanking({ data, loading }: Props) {
  return (
    <div className="bg-slate-800 rounded-2xl p-6 border border-slate-700">
      <div className="flex items-center gap-2 mb-5">
        <Trophy size={18} className="text-slate-400" />
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">ベンダー別脆弱性数 Top 10</h2>
      </div>

      {loading ? (
        <div className="h-64 flex items-center justify-center text-slate-500">読み込み中...</div>
      ) : data.length === 0 ? (
        <div className="h-64 flex items-center justify-center text-slate-500">データなし</div>
      ) : (
        <ResponsiveContainer width="100%" height={280}>
          <BarChart
            data={data}
            layout="vertical"
            margin={{ top: 0, right: 30, left: 10, bottom: 0 }}
          >
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" horizontal={false} />
            <XAxis
              type="number"
              tick={{ fill: '#94a3b8', fontSize: 11 }}
              tickLine={false}
              axisLine={false}
              allowDecimals={false}
            />
            <YAxis
              type="category"
              dataKey="vendor_project"
              tick={{ fill: '#cbd5e1', fontSize: 11 }}
              tickLine={false}
              axisLine={false}
              width={90}
            />
            <Tooltip content={<CustomTooltip />} />
            <Bar dataKey="count" radius={[0, 4, 4, 0]}>
              {data.map((_, index) => (
                <Cell key={index} fill={BAR_COLORS[index] ?? '#7c3aed'} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}
