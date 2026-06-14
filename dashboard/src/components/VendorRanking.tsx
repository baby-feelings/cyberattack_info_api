import { Trophy } from 'lucide-react'
import type { VendorStat } from '../api/client'

interface Props {
  data: VendorStat[]
  loading: boolean
}

const MEDAL = ['🥇', '🥈', '🥉']
const BAR_COLOR = [
  'bg-amber-400', 'bg-slate-400', 'bg-orange-600',
  'bg-violet-500', 'bg-violet-500', 'bg-violet-500',
  'bg-violet-500', 'bg-violet-500', 'bg-violet-500', 'bg-violet-500',
]

export function VendorRanking({ data, loading }: Props) {
  const maxCount = data[0]?.count ?? 1

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg flex flex-col gap-4">

      <div className="flex items-center gap-2">
        <Trophy size={15} className="text-slate-400" />
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
          ベンダー別脆弱性数 Top 10
        </span>
      </div>

      {loading ? (
        <div className="space-y-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="flex items-center gap-3">
              <div className="w-4 h-3 bg-slate-800 rounded animate-pulse shrink-0" />
              <div className="flex-1 h-3 bg-slate-800 rounded animate-pulse" style={{ width: `${80 - i * 10}%` }} />
              <div className="w-10 h-3 bg-slate-800 rounded animate-pulse" />
            </div>
          ))}
        </div>
      ) : data.length === 0 ? (
        <p className="text-xs text-slate-600 text-center py-8">データがありません</p>
      ) : (
        <div className="space-y-2.5">
          {data.map((item, i) => (
            <div key={item.vendor_project} className="flex items-center gap-3 group">
              {/* 順位 */}
              <span className="text-sm w-5 text-center shrink-0 leading-none">
                {MEDAL[i] ?? <span className="text-xs text-slate-600 font-mono">{i + 1}</span>}
              </span>

              {/* ベンダー名 + バー */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-slate-300 truncate pr-2 group-hover:text-white transition-colors">
                    {item.vendor_project}
                  </span>
                  <span className="text-xs font-semibold text-slate-400 shrink-0 tabular-nums">
                    {item.count.toLocaleString()}
                  </span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full ${BAR_COLOR[i]} transition-all duration-700`}
                    style={{ width: `${(item.count / maxCount) * 100}%` }}
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
