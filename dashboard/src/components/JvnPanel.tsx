import { useCallback, useEffect, useState } from 'react'
import { FileWarning, RefreshCw, Search, X } from 'lucide-react'
import {
  fetchJvnList, fetchJvnStats,
  type JvnListResponse, type JvnStatsResponse,
} from '../api/client'
import {
  SeverityPieChart, MonthlyBarChart,
  TableLoadingSkeleton, EmptyState, Pagination,
  SeverityFilterButtons, SearchBox, SortSelector,
} from './shared/VulnPanelParts'
import { JvnRow } from './jvn/JvnRow'

// JVN の重要度は High / Medium / Low（OSV とは異なる）
const SEVERITY_CLS: Record<string, string> = {
  High:   'bg-orange-500/15 text-orange-400 border-orange-500/30',
  Medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  Low:    'bg-blue-500/15 text-blue-400 border-blue-500/30',
}

const SEVERITY_COLORS: Record<string, string> = {
  High:   '#f97316',
  Medium: '#eab308',
  Low:    '#3b82f6',
  'N/A':  '#475569',
}

const SEVERITIES = ['ALL', 'High', 'Medium', 'Low']
const PER_PAGE = 30

export function JvnPanel() {
  const [severity, setSeverity] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [sortBy, setSortBy] = useState<'modified' | 'cvss'>('modified')
  const [page, setPage] = useState(1)
  const [result, setResult] = useState<JvnListResponse | null>(null)
  const [stats, setStats] = useState<JvnStatsResponse | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async (
    sev: string | null, q: string,
    p: number, sort: 'modified' | 'cvss',
  ) => {
    setLoading(true)
    try {
      const [list, st] = await Promise.all([
        fetchJvnList({ severity: sev, search: q, page: p, perPage: PER_PAGE, sortBy: sort }),
        fetchJvnStats(180),
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
    load(severity, search, page, sortBy)
  }, [load, severity, search, page, sortBy])

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
  const highCount = stats?.severities.find(s => s.severity === 'High')?.count ?? 0
  const medCount  = stats?.severities.find(s => s.severity === 'Medium')?.count ?? 0

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg flex flex-col gap-5">

      {/* ヘッダー */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <FileWarning size={16} className="text-slate-400" />
          <span className="text-sm font-semibold text-slate-400 uppercase tracking-wider">
            JVN 脆弱性（過去 6 ヶ月）
          </span>
        </div>
        <div className="flex items-center gap-3">
          {!loading && stats && stats.total > 0 && (
            <div className="flex items-center gap-2 text-xs tabular-nums">
              {highCount > 0 && (
                <span className="px-2 py-0.5 rounded-full bg-orange-500/15 text-orange-400 font-semibold">
                  HIGH {highCount}
                </span>
              )}
              {medCount > 0 && (
                <span className="px-2 py-0.5 rounded-full bg-yellow-500/15 text-yellow-400 font-semibold">
                  MED {medCount}
                </span>
              )}
              <span className="text-slate-500">/ {stats.total} 件</span>
            </div>
          )}
          <button
            onClick={() => load(severity, search, page, sortBy)}
            disabled={loading}
            className="text-slate-500 hover:text-slate-300 transition-colors disabled:opacity-40 p-1 rounded"
            title="再読み込み"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* ビジュアライゼーション: 重要度別グラフ・月別トレンド */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <SeverityPieChart
          icon={<FileWarning size={13} className="text-slate-400" />}
          data={stats?.severities ?? []}
          colorMap={SEVERITY_COLORS}
          loading={loading}
        />
        <MonthlyBarChart
          icon={<FileWarning size={13} className="text-slate-400" />}
          title="月別 JVN 更新トレンド"
          data={stats?.monthly_trend ?? []}
          barColor="#f59e0b"
          height={210}
          loading={loading}
        />
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
          placeholder="JVNDB ID・タイトル・概要"
          searchIcon={<Search size={11} className="text-slate-500 shrink-0" />}
          clearIcon={<X size={10} />}
        />

        <SortSelector
          sortBy={sortBy}
          onChange={sort => { setSortBy(sort); setPage(1) }}
          activeClass="bg-amber-500 text-white"
        />
      </div>

      {/* ローディング */}
      {loading ? (
        <TableLoadingSkeleton columnWidths={['w-16', 'w-36', 'flex-1', 'w-28']} />

      /* データなし */
      ) : result && result.total === 0 ? (
        <EmptyState icon={<FileWarning size={28} />} message="該当する JVN 脆弱性はありません" />

      /* テーブル */
      ) : result && (
        <>
          <div className="overflow-x-auto -mx-1 px-1">
            <table className="w-full text-sm min-w-[700px]">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-20">深刻度</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-48">JVNDB ID</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3">タイトル</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-44">影響製品</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-24">更新日</th>
                  <th className="w-5" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {result.data.map((item, i) => (
                  <JvnRow
                    key={`${item.jvndb_id}-${i}`}
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
