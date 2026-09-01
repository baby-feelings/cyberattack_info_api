import { useCallback, useEffect, useState } from 'react'
import {
  FileWarning, ExternalLink, ChevronDown, ChevronUp,
  RefreshCw, Search, X,
} from 'lucide-react'
import {
  fetchJvnList, fetchJvnStats,
  type JvnVulnerabilityOut, type JvnListResponse, type JvnStatsResponse,
} from '../api/client'
import {
  SeverityBadge, SeverityPieChart, MonthlyBarChart,
  TableLoadingSkeleton, EmptyState, Pagination,
  SeverityFilterButtons, SearchBox, SortSelector,
} from './shared/VulnPanelParts'

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

function JvnRow({ item }: { item: JvnVulnerabilityOut }) {
  const [open, setOpen] = useState(false)
  const modifiedDate = new Date(item.date_last_modified).toLocaleDateString('ja-JP', {
    year: 'numeric', month: 'short', day: 'numeric',
  })
  // 最初の影響製品（代表表示）
  const firstProduct = item.affected_products[0]

  return (
    <>
      <tr
        className="hover:bg-slate-800/40 transition-colors cursor-pointer"
        onClick={() => setOpen(o => !o)}
      >
        {/* 深刻度 + CVSS */}
        <td className="py-2.5 pr-3 w-20">
          <SeverityBadge severity={item.severity} classMap={SEVERITY_CLS} />
          {item.cvss_score != null && (
            <span className="block text-[10px] text-slate-600 mt-0.5 tabular-nums">
              {item.cvss_score.toFixed(1)}
            </span>
          )}
        </td>

        {/* JVNDB ID */}
        <td className="py-2.5 pr-3 w-48">
          <a
            href={item.jvn_url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 font-mono text-amber-400 hover:text-amber-300 text-xs transition-colors"
            onClick={e => e.stopPropagation()}
          >
            {item.jvndb_id}
            <ExternalLink size={9} />
          </a>
          {/* 関連 CVE ID */}
          {item.cve_ids.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-0.5">
              {item.cve_ids.slice(0, 2).map(cve => (
                <a
                  key={cve}
                  href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[10px] font-mono text-slate-500 hover:text-slate-300"
                  onClick={e => e.stopPropagation()}
                >
                  {cve}
                </a>
              ))}
            </div>
          )}
        </td>

        {/* タイトル */}
        <td className="py-2.5 pr-3">
          <p className="text-slate-300 text-xs line-clamp-2">{item.title}</p>
        </td>

        {/* 影響製品（代表） */}
        <td className="py-2.5 pr-3 w-44">
          {firstProduct ? (
            <p className="text-slate-400 text-xs truncate">
              <span className="text-slate-500">{firstProduct.vendor} / </span>
              {firstProduct.product}
            </p>
          ) : (
            <span className="text-slate-700 text-xs">—</span>
          )}
          {item.affected_products.length > 1 && (
            <p className="text-[10px] text-slate-600 mt-0.5">+{item.affected_products.length - 1} 製品</p>
          )}
        </td>

        {/* 更新日 */}
        <td className="py-2.5 text-xs text-slate-600 tabular-nums whitespace-nowrap w-24">
          {modifiedDate}
        </td>

        {/* 展開トグル */}
        <td className="py-2.5 pl-2 text-right w-5">
          {open
            ? <ChevronUp size={12} className="text-slate-500 ml-auto" />
            : <ChevronDown size={12} className="text-slate-500 ml-auto" />}
        </td>
      </tr>

      {/* 展開: 概要・影響製品全件・CVSS ベクター */}
      {open && (
        <tr className="bg-slate-800/30">
          <td colSpan={6} className="px-4 py-3 text-xs text-slate-400 space-y-2.5">
            {/* 概要 */}
            <p className="leading-relaxed whitespace-pre-wrap">{item.overview}</p>

            {/* CVSS ベクター */}
            {item.cvss_vector && (
              <p className="flex items-center gap-1.5">
                <span className="text-slate-500">CVSS ベクター:</span>
                <span className="font-mono text-slate-400 text-[10px] bg-slate-800 px-1.5 py-0.5 rounded">
                  {item.cvss_vector}
                </span>
              </p>
            )}

            {/* 関連 CVE (全件) */}
            {item.cve_ids.length > 0 && (
              <p className="flex flex-wrap items-center gap-1.5">
                <span className="text-slate-500">関連 CVE:</span>
                {item.cve_ids.map(cve => (
                  <a
                    key={cve}
                    href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[10px] font-mono text-violet-400 hover:text-violet-300"
                  >
                    {cve}
                  </a>
                ))}
              </p>
            )}

            {/* 影響製品（全件） */}
            {item.affected_products.length > 0 && (
              <div>
                <p className="text-slate-500 mb-1">影響製品:</p>
                <div className="flex flex-wrap gap-1.5">
                  {item.affected_products.map((p, i) => (
                    <span
                      key={i}
                      className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-[10px] text-slate-400"
                    >
                      {p.vendor} / {p.product}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* JVNDB リンク */}
            <a
              href={item.jvn_url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-amber-400 hover:text-amber-300 underline underline-offset-2 text-[10px]"
            >
              JVNDB で詳細を確認
              <ExternalLink size={9} />
            </a>
          </td>
        </tr>
      )}
    </>
  )
}

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
                  <JvnRow key={`${item.jvndb_id}-${i}`} item={item} />
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
