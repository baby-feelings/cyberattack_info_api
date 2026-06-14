import { useState } from 'react'
import { AlertTriangle, ExternalLink, ChevronLeft, ChevronRight } from 'lucide-react'
import type { VulnerabilityOut } from '../api/client'

interface Props {
  data: VulnerabilityOut[]
  loading: boolean
}

const PAGE_SIZE = 8

// 日付から経過日数を計算してバッジ色を返す
function getDateBadge(dateStr: string) {
  const days = Math.floor((Date.now() - new Date(dateStr).getTime()) / 86400000)
  if (days <= 7) return { label: `${days}d ago`, cls: 'bg-red-500/15 text-red-400 border-red-500/30' }
  if (days <= 14) return { label: `${days}d ago`, cls: 'bg-orange-500/15 text-orange-400 border-orange-500/30' }
  return { label: dateStr, cls: 'bg-slate-800 text-slate-500 border-slate-700' }
}

export function RecentCVEs({ data, loading }: Props) {
  const [page, setPage] = useState(0)
  const totalPages = Math.ceil(data.length / PAGE_SIZE)
  const paged = data.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg flex flex-col gap-4">

      {/* ヘッダー */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <AlertTriangle size={16} className="text-slate-400" />
          <span className="text-sm font-semibold text-slate-400 uppercase tracking-wider">
            直近 30 日の新規 CVE
          </span>
        </div>
        {!loading && (
          <span className="text-sm font-medium text-slate-500 tabular-nums">
            {data.length} 件
          </span>
        )}
      </div>

      {/* テーブル本体 */}
      {loading ? (
        <div className="space-y-2">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="flex items-center gap-3 py-2">
              <div className="h-3 w-28 bg-slate-800 rounded animate-pulse" />
              <div className="h-3 flex-1 bg-slate-800 rounded animate-pulse" />
              <div className="h-3 w-16 bg-slate-800 rounded animate-pulse" />
            </div>
          ))}
        </div>
      ) : data.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-2 py-10 text-slate-600">
          <AlertTriangle size={24} />
          <p className="text-xs">直近 30 日の新規 CVE はありません</p>
        </div>
      ) : (
        <>
          <div className="overflow-x-auto -mx-1 px-1">
            <table className="w-full text-sm min-w-[480px]">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-36">CVE ID</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3">ベンダー / 製品</th>
                  <th className="text-right text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 w-24">追加日</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {paged.map((v) => {
                  const badge = getDateBadge(v.date_added)
                  return (
                    <tr key={v.cve_id} className="hover:bg-slate-800/40 transition-colors group">
                      <td className="py-3 pr-3">
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 font-mono text-violet-400 hover:text-violet-300 transition-colors"
                        >
                          {v.cve_id}
                          <ExternalLink size={11} className="opacity-0 group-hover:opacity-100 transition-opacity" />
                        </a>
                      </td>
                      <td className="py-2.5 pr-3">
                        <p className="text-slate-300 font-medium truncate max-w-[200px]">{v.vendor_project}</p>
                        <p className="text-slate-500 text-xs truncate max-w-[200px]">{v.product}</p>
                      </td>
                      <td className="py-2.5 text-right">
                        <span className={`inline-block px-2 py-0.5 rounded border text-xs font-medium ${badge.cls}`}>
                          {badge.label}
                        </span>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          {/* ページネーション */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between pt-2 border-t border-slate-800">
              <button
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={page === 0}
                className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-sm text-slate-300 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronLeft size={12} /> 前へ
              </button>
              <span className="text-sm text-slate-600 tabular-nums">
                {page + 1} / {totalPages}
              </span>
              <button
                onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                disabled={page === totalPages - 1}
                className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-sm text-slate-300 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                次へ <ChevronRight size={12} />
              </button>
            </div>
          )}
        </>
      )}
    </div>
  )
}
