// 直近 30 日の新規 CVE 一覧テーブル
import { useState } from 'react'
import { AlertTriangle, ExternalLink } from 'lucide-react'
import type { VulnerabilityOut } from '../api/client'

interface Props {
  data: VulnerabilityOut[]
  loading: boolean
}

const PAGE_SIZE = 10

export function RecentCVEs({ data, loading }: Props) {
  const [page, setPage] = useState(0)
  const totalPages = Math.ceil(data.length / PAGE_SIZE)
  const paged = data.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  return (
    <div className="bg-slate-800 rounded-2xl p-6 border border-slate-700">
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-2">
          <AlertTriangle size={18} className="text-slate-400" />
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
            直近 30 日の新規 CVE
          </h2>
        </div>
        <span className="text-xs text-slate-500">{data.length} 件</span>
      </div>

      {loading ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-12 bg-slate-700/50 rounded-lg animate-pulse" />
          ))}
        </div>
      ) : data.length === 0 ? (
        <p className="text-slate-500 text-sm text-center py-8">直近 30 日の新規 CVE はありません</p>
      ) : (
        <>
          <div className="overflow-x-auto -mx-1">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-slate-500 border-b border-slate-700">
                  <th className="pb-2 pr-4 font-medium">CVE ID</th>
                  <th className="pb-2 pr-4 font-medium">ベンダー</th>
                  <th className="pb-2 pr-4 font-medium hidden md:table-cell">製品</th>
                  <th className="pb-2 pr-4 font-medium hidden lg:table-cell">脆弱性名</th>
                  <th className="pb-2 font-medium">追加日</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {paged.map((v) => (
                  <tr key={v.cve_id} className="hover:bg-slate-700/30 transition-colors">
                    <td className="py-2.5 pr-4">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-violet-400 hover:text-violet-300 font-mono text-xs flex items-center gap-1 whitespace-nowrap"
                      >
                        {v.cve_id}
                        <ExternalLink size={10} />
                      </a>
                    </td>
                    <td className="py-2.5 pr-4 text-slate-300 text-xs whitespace-nowrap">{v.vendor_project}</td>
                    <td className="py-2.5 pr-4 text-slate-400 text-xs hidden md:table-cell">{v.product}</td>
                    <td className="py-2.5 pr-4 text-slate-400 text-xs hidden lg:table-cell max-w-xs truncate">
                      {v.vulnerability_name}
                    </td>
                    <td className="py-2.5 text-slate-500 text-xs whitespace-nowrap">{v.date_added}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* ページネーション */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between mt-4 pt-4 border-t border-slate-700">
              <button
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={page === 0}
                className="text-xs px-3 py-1.5 rounded-lg bg-slate-700 text-slate-300 disabled:opacity-40 hover:bg-slate-600 transition-colors"
              >
                ← 前へ
              </button>
              <span className="text-xs text-slate-500">
                {page + 1} / {totalPages} ページ
              </span>
              <button
                onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                disabled={page === totalPages - 1}
                className="text-xs px-3 py-1.5 rounded-lg bg-slate-700 text-slate-300 disabled:opacity-40 hover:bg-slate-600 transition-colors"
              >
                次へ →
              </button>
            </div>
          )}
        </>
      )}
    </div>
  )
}
