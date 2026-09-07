import { useCallback, useEffect, useState } from 'react'
import { Shield, RefreshCw, Search, X, BarChart2 } from 'lucide-react'
import {
  fetchVulnerabilities, fetchStats, fetchRecent,
  type VulnerabilityListResponse, type StatsResponse,
} from '../api/client'
import {
  MonthlyBarChart,
  TableLoadingSkeleton, EmptyState, Pagination, SearchBox,
} from './shared/VulnPanelParts'
import { KevRow } from './kev/KevRow'
import { VendorBarChart } from './kev/VendorBarChart'

const PER_PAGE = 30

export function KevPanel() {
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [result, setResult] = useState<VulnerabilityListResponse | null>(null)
  const [stats, setStats] = useState<StatsResponse | null>(null)
  const [recentCount, setRecentCount] = useState(0)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async (q: string, p: number) => {
    setLoading(true)
    try {
      const [list, st, recent] = await Promise.all([
        fetchVulnerabilities({ search: q, page: p, perPage: PER_PAGE }),
        fetchStats(),
        fetchRecent(30),
      ])
      setResult(list)
      setStats(st)
      setRecentCount(recent.length)
    } catch {
      // エラーは握りつぶし（データなし状態として扱う）
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load(search, page)
  }, [load, search, page])

  function clearSearch() {
    setSearch('')
    setPage(1)
  }

  const totalPages = result ? Math.ceil(result.total / PER_PAGE) : 0

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg flex flex-col gap-5">

      {/* ヘッダー */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield size={16} className="text-slate-400" />
          <span className="text-sm font-semibold text-slate-400 uppercase tracking-wider">
            CISA KEV — 悪用が確認された脆弱性
          </span>
        </div>
        <div className="flex items-center gap-3">
          {!loading && stats && stats.total_vulnerabilities > 0 && (
            <div className="flex items-center gap-2 text-xs tabular-nums">
              {recentCount > 0 && (
                <span className="px-2 py-0.5 rounded-full bg-sky-500/15 text-sky-400 font-semibold">
                  直近30日 {recentCount}
                </span>
              )}
              <span className="text-slate-500">/ {stats.total_vulnerabilities} 件</span>
            </div>
          )}
          <button
            onClick={() => load(search, page)}
            disabled={loading}
            className="text-slate-500 hover:text-slate-300 transition-colors disabled:opacity-40 p-1 rounded"
            title="再読み込み"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* ビジュアライゼーション: ベンダー別・月別トレンド */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <VendorBarChart stats={stats} loading={loading} />
        <MonthlyBarChart
          icon={<BarChart2 size={13} className="text-slate-400" />}
          title="月別 CVE 追加数トレンド"
          data={stats?.monthly_trend ?? []}
          barColor="#7c3aed"
          height={160}
          loading={loading}
        />
      </div>

      {/* 検索 */}
      <div className="flex flex-wrap items-center gap-3">
        <SearchBox
          value={search}
          onChange={v => { setSearch(v); setPage(1) }}
          onClear={clearSearch}
          placeholder="ベンダー名・製品名"
          searchIcon={<Search size={11} className="text-slate-500 shrink-0" />}
          clearIcon={<X size={10} />}
        />
      </div>

      {/* ローディング */}
      {loading ? (
        <TableLoadingSkeleton columnWidths={['w-28', 'w-28', 'w-28', 'flex-1']} />

      /* データなし */
      ) : result && result.total === 0 ? (
        <EmptyState icon={<Shield size={28} />} message="該当する CVE はありません" />

      /* テーブル */
      ) : result && (
        <>
          <div className="overflow-x-auto -mx-1 px-1">
            <table className="w-full text-sm min-w-[700px]">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-36">CVE ID</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-16">EPSS</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-40">ベンダー</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-40">製品</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3">脆弱性名</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-24">追加日</th>
                  <th className="w-5" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {result.data.map(item => (
                  <KevRow key={item.cve_id} item={item} />
                ))}
              </tbody>
            </table>
          </div>

          <Pagination page={page} totalPages={totalPages} total={result.total} onPageChange={setPage} />
        </>
      )}
    </div>
  )
}
