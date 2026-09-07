import { useCallback, useEffect, useState } from 'react'
import { Shield, RefreshCw, Search, X, BarChart2 } from 'lucide-react'
import {
  fetchOsvList, fetchOsvStats,
  type OsvListResponse, type OsvStatsResponse,
} from '../api/client'
import {
  SeverityPieChart, MonthlyBarChart,
  TableLoadingSkeleton, EmptyState, Pagination,
  SeverityFilterButtons, SearchBox, SortSelector,
} from './shared/VulnPanelParts'
import { OsvRow } from './osv/OsvRow'
import { EcosystemBarChart } from './osv/EcosystemBarChart'

// 深刻度バッジのスタイル
const SEVERITY_CLS: Record<string, string> = {
  CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
  HIGH:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
  MEDIUM:   'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  LOW:      'bg-blue-500/15 text-blue-400 border-blue-500/30',
}

// 重要度別グラフの色
const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#3b82f6',
  'N/A':    '#475569',
}

const ECOSYSTEMS = ['ALL', 'PyPI', 'npm', 'Go', 'Maven', 'RubyGems', 'NuGet', 'crates.io', 'Packagist', 'Hex', 'Pub']
const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const PER_PAGE = 30

export function OsvPanel() {
  const [ecosystem, setEcosystem] = useState<string | null>(null)
  const [severity, setSeverity] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [sortBy, setSortBy] = useState<'modified' | 'cvss'>('modified')
  const [page, setPage] = useState(1)
  const [result, setResult] = useState<OsvListResponse | null>(null)
  const [stats, setStats] = useState<OsvStatsResponse | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async (
    eco: string | null, sev: string | null, q: string,
    p: number, sort: 'modified' | 'cvss',
  ) => {
    setLoading(true)
    try {
      const [list, st] = await Promise.all([
        fetchOsvList({ ecosystem: eco, severity: sev, search: q, page: p, perPage: PER_PAGE, sortBy: sort }),
        fetchOsvStats(180),
      ])
      setResult(list)
      setStats(st)
    } catch {
      // エラーは握りつぶし（データなし状態として扱う）
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load(ecosystem, severity, search, page, sortBy)
  }, [load, ecosystem, severity, search, page, sortBy])

  function handleEco(eco: string) {
    setEcosystem(eco === 'ALL' ? null : eco)
    setPage(1)
  }

  function handleSev(sev: string) {
    setSeverity(sev === 'ALL' ? null : sev)
    setPage(1)
  }

  function clearSearch() {
    setSearch('')
    setPage(1)
  }

  const totalPages = result ? Math.ceil(result.total / PER_PAGE) : 0

  // 重要度別カウントをヘッダーに表示
  const critCount = stats?.severities.find(s => s.severity === 'CRITICAL')?.count ?? 0
  const highCount = stats?.severities.find(s => s.severity === 'HIGH')?.count ?? 0

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg flex flex-col gap-5">

      {/* ヘッダー */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield size={16} className="text-slate-400" />
          <span className="text-sm font-semibold text-slate-400 uppercase tracking-wider">
            OSV 脆弱性（過去 6 ヶ月）
          </span>
        </div>
        <div className="flex items-center gap-3">
          {/* CRITICAL / HIGH カウント */}
          {!loading && stats && stats.total > 0 && (
            <div className="flex items-center gap-2 text-xs tabular-nums">
              {critCount > 0 && (
                <span className="px-2 py-0.5 rounded-full bg-red-500/15 text-red-400 font-semibold">
                  CRIT {critCount}
                </span>
              )}
              {highCount > 0 && (
                <span className="px-2 py-0.5 rounded-full bg-orange-500/15 text-orange-400 font-semibold">
                  HIGH {highCount}
                </span>
              )}
              <span className="text-slate-500">/ {stats.total} 件</span>
            </div>
          )}
          <button
            onClick={() => load(ecosystem, severity, search, page, sortBy)}
            disabled={loading}
            className="text-slate-500 hover:text-slate-300 transition-colors disabled:opacity-40 p-1 rounded"
            title="再読み込み"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* ビジュアライゼーション: 重要度別グラフ・エコシステム別・月別トレンド */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <SeverityPieChart
          icon={<Shield size={13} className="text-slate-400" />}
          data={stats?.severities ?? []}
          colorMap={SEVERITY_COLORS}
          loading={loading}
        />
        <EcosystemBarChart stats={stats} loading={loading} />
        <MonthlyBarChart
          icon={<BarChart2 size={13} className="text-slate-400" />}
          title="月別 OSV 更新トレンド"
          data={stats?.monthly_trend ?? []}
          barColor="#7c3aed"
          height={160}
          loading={loading}
        />
      </div>

      {/* エコシステムフィルター */}
      <div className="flex flex-wrap gap-1.5">
        {ECOSYSTEMS.map(eco => {
          const active = (eco === 'ALL' && ecosystem === null) || eco === ecosystem
          return (
            <button
              key={eco}
              onClick={() => handleEco(eco)}
              className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors ${
                active
                  ? 'bg-violet-600 text-white shadow'
                  : 'bg-slate-800 text-slate-400 hover:text-slate-300 hover:bg-slate-700'
              }`}
            >
              {eco}
              {/* エコシステム別件数を表示 */}
              {eco !== 'ALL' && stats && (
                <span className="ml-1 opacity-60">
                  {stats.ecosystems.find(e => e.ecosystem === eco)?.count ?? 0}
                </span>
              )}
            </button>
          )
        })}
      </div>

      {/* 重要度フィルター + 検索 + ソート */}
      <div className="flex flex-wrap items-center gap-3">
        <SeverityFilterButtons
          severities={SEVERITIES}
          active={severity}
          onSelect={handleSev}
          classMap={SEVERITY_CLS}
        />

        <SearchBox
          value={search}
          onChange={v => { setSearch(v); setPage(1) }}
          onClear={clearSearch}
          placeholder="OSV ID・パッケージ名・概要"
          searchIcon={<Search size={11} className="text-slate-500 shrink-0" />}
          clearIcon={<X size={10} />}
        />

        <SortSelector
          sortBy={sortBy}
          onChange={sort => { setSortBy(sort); setPage(1) }}
          activeClass="bg-violet-600 text-white"
        />
      </div>

      {/* ローディング */}
      {loading ? (
        <TableLoadingSkeleton columnWidths={['w-16', 'w-28', 'w-16', 'flex-1']} />

      /* データなし */
      ) : result && result.total === 0 ? (
        <EmptyState icon={<Shield size={28} />} message="該当する OSV 脆弱性はありません" />

      /* テーブル */
      ) : result && (
        <>
          <div className="overflow-x-auto -mx-1 px-1">
            <table className="w-full text-sm min-w-[700px]">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-20">深刻度</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-44">OSV ID</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-24">エコシステム</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-36">パッケージ</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3">概要</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-24">更新日</th>
                  <th className="w-5" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {result.data.map((item, i) => (
                  <OsvRow
                    key={`${item.osv_id}-${item.ecosystem}-${item.package_name}-${i}`}
                    item={item}
                    severityClassMap={SEVERITY_CLS}
                  />
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
