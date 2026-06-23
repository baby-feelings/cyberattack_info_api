import { useCallback, useEffect, useState } from 'react'
import {
  Shield, ExternalLink, ChevronDown, ChevronUp,
  Loader2, RefreshCw, Search, X, TrendingUp, BarChart2,
} from 'lucide-react'
import {
  PieChart, Pie, Cell, Tooltip as ReTooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from 'recharts'
import {
  fetchOsvList, fetchOsvStats,
  type OsvVulnerabilityOut, type OsvListResponse, type OsvStatsResponse,
} from '../api/client'

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

// エコシステムバッジの色
const ECO_COLOR: Record<string, string> = {
  PyPI:       'bg-sky-500/15 text-sky-400',
  npm:        'bg-red-500/15 text-red-400',
  Go:         'bg-cyan-500/15 text-cyan-400',
  Maven:      'bg-amber-500/15 text-amber-400',
  RubyGems:   'bg-rose-500/15 text-rose-400',
  NuGet:      'bg-violet-500/15 text-violet-400',
  'crates.io': 'bg-orange-500/15 text-orange-400',
  Packagist:  'bg-indigo-500/15 text-indigo-400',
  Hex:        'bg-emerald-500/15 text-emerald-400',
  Pub:        'bg-teal-500/15 text-teal-400',
}

// エコシステム別グラフの色（順番で割り当て）
const ECO_CHART_COLORS = [
  '#7c3aed', '#0ea5e9', '#22d3ee', '#f59e0b',
  '#f43f5e', '#8b5cf6', '#f97316', '#6366f1', '#10b981', '#14b8a6',
]

const ECOSYSTEMS = ['ALL', 'PyPI', 'npm', 'Go', 'Maven', 'RubyGems', 'NuGet', 'crates.io', 'Packagist', 'Hex', 'Pub']
const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const PER_PAGE = 30

function SeverityBadge({ severity }: { severity: string | null }) {
  const cls = severity
    ? (SEVERITY_CLS[severity] ?? 'bg-slate-800 text-slate-400 border-slate-700')
    : 'bg-slate-800 text-slate-500 border-slate-700'
  return (
    <span className={`inline-block px-1.5 py-0.5 rounded border text-xs font-semibold whitespace-nowrap ${cls}`}>
      {severity ?? 'N/A'}
    </span>
  )
}

function EcoBadge({ eco }: { eco: string }) {
  const cls = ECO_COLOR[eco] ?? 'bg-slate-700 text-slate-400'
  return (
    <span className={`inline-block px-1.5 py-0.5 rounded text-xs font-medium whitespace-nowrap ${cls}`}>
      {eco}
    </span>
  )
}

function OsvRow({ item }: { item: OsvVulnerabilityOut }) {
  const [open, setOpen] = useState(false)
  const cveAliases = item.aliases.filter(a => a.startsWith('CVE-'))
  const modifiedDate = new Date(item.modified).toLocaleDateString('ja-JP', {
    year: 'numeric', month: 'short', day: 'numeric',
  })

  return (
    <>
      <tr
        className="hover:bg-slate-800/40 transition-colors cursor-pointer"
        onClick={() => setOpen(o => !o)}
      >
        <td className="py-2.5 pr-3">
          <SeverityBadge severity={item.severity} />
          {item.cvss_score != null && (
            <span className="block text-[10px] text-slate-600 mt-0.5 tabular-nums">
              {item.cvss_score.toFixed(1)}
            </span>
          )}
        </td>
        <td className="py-2.5 pr-3">
          {/* OSV ID */}
          <a
            href={`https://osv.dev/vulnerability/${item.osv_id}`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 font-mono text-violet-400 hover:text-violet-300 text-xs transition-colors"
            onClick={e => e.stopPropagation()}
          >
            {item.osv_id}
            <ExternalLink size={9} />
          </a>
          {/* CVE エイリアス */}
          {cveAliases.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-0.5">
              {cveAliases.slice(0, 2).map(cve => (
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
        <td className="py-2.5 pr-3">
          <EcoBadge eco={item.ecosystem} />
        </td>
        <td className="py-2.5 pr-3">
          <p className="text-slate-300 font-mono text-xs">{item.package_name}</p>
          {item.fixed_versions.length > 0 && (
            <p className="text-emerald-500 text-[10px] mt-0.5">
              fix: {item.fixed_versions[0]}
            </p>
          )}
        </td>
        <td className="py-2.5 pr-3">
          <p className="text-slate-400 text-xs truncate max-w-[240px]">{item.summary}</p>
        </td>
        <td className="py-2.5 text-xs text-slate-600 tabular-nums whitespace-nowrap">
          {modifiedDate}
        </td>
        <td className="py-2.5 pl-2 text-right">
          {open
            ? <ChevronUp size={12} className="text-slate-500 ml-auto" />
            : <ChevronDown size={12} className="text-slate-500 ml-auto" />}
        </td>
      </tr>

      {/* 展開: 詳細・修正バージョン・参考リンク */}
      {open && (
        <tr className="bg-slate-800/30">
          <td colSpan={7} className="px-4 py-3 text-xs text-slate-400 space-y-2">
            {item.details && (
              <p className="leading-relaxed whitespace-pre-wrap">{item.details}</p>
            )}
            {item.fixed_versions.length > 0 && (
              <p className="flex flex-wrap items-center gap-1.5">
                <span className="text-slate-500">修正済みバージョン:</span>
                {item.fixed_versions.map(v => (
                  <span key={v} className="px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 text-[10px] font-mono">
                    {v}
                  </span>
                ))}
              </p>
            )}
            {item.aliases.length > 0 && (
              <p className="flex flex-wrap items-center gap-1.5">
                <span className="text-slate-500">エイリアス:</span>
                {item.aliases.map(a => (
                  <span key={a} className="text-[10px] font-mono text-slate-500">{a}</span>
                ))}
              </p>
            )}
            {item.references.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {item.references.map(url => (
                  <a
                    key={url}
                    href={url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-violet-400 hover:text-violet-300 underline underline-offset-2 text-[10px] break-all"
                  >
                    {url}
                  </a>
                ))}
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  )
}

// 重要度別円グラフ
function SeverityPieChart({ stats, loading }: { stats: OsvStatsResponse | null; loading: boolean }) {
  const data = (stats?.severities ?? [])
    .filter(s => s.severity !== 'N/A' && s.count > 0)
    .map(s => ({ name: s.severity, value: s.count }))

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <Shield size={13} className="text-slate-400" />
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">重要度別分布</span>
      </div>
      <div className="h-[210px]">
        {loading || data.length === 0 ? (
          <div className="h-full flex items-center justify-center text-xs text-slate-600">
            {loading ? '読み込み中...' : 'データなし'}
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="50%"
                innerRadius={55}
                outerRadius={85}
                paddingAngle={2}
                dataKey="value"
              >
                {data.map((entry) => (
                  <Cell
                    key={entry.name}
                    fill={SEVERITY_COLORS[entry.name] ?? '#475569'}
                  />
                ))}
              </Pie>
              <ReTooltip
                contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
                formatter={(value, name) => [String(value) + ' 件', String(name)]}
              />
            </PieChart>
          </ResponsiveContainer>
        )}
      </div>
      {/* 凡例 */}
      {!loading && data.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {data.map(d => (
            <span key={d.name} className="flex items-center gap-1 text-[11px] text-slate-400">
              <span
                className="inline-block w-2 h-2 rounded-full"
                style={{ background: SEVERITY_COLORS[d.name] ?? '#475569' }}
              />
              {d.name} <span className="text-slate-600">{d.value}</span>
            </span>
          ))}
        </div>
      )}
    </div>
  )
}

// エコシステム別棒グラフ
function EcosystemBarChart({ stats, loading }: { stats: OsvStatsResponse | null; loading: boolean }) {
  // 上位 8 エコシステムのみ表示
  const data = (stats?.ecosystems ?? []).slice(0, 8)

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <BarChart2 size={13} className="text-slate-400" />
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">エコシステム別件数</span>
      </div>
      <div className="h-[160px]">
        {loading || data.length === 0 ? (
          <div className="h-full flex items-center justify-center text-xs text-slate-600">
            {loading ? '読み込み中...' : 'データなし'}
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis
                dataKey="ecosystem"
                tick={{ fill: '#475569', fontSize: 10 }}
                tickLine={false}
                axisLine={false}
              />
              <YAxis
                tick={{ fill: '#475569', fontSize: 10 }}
                tickLine={false}
                axisLine={false}
                allowDecimals={false}
              />
              <ReTooltip
                contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
                formatter={(value) => [String(value) + ' 件', '件数']}
              />
              <Bar dataKey="count" radius={[3, 3, 0, 0]}>
                {data.map((_entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={ECO_CHART_COLORS[index % ECO_CHART_COLORS.length]}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  )
}

// 月別 OSV トレンドグラフ
function OsvMonthlyChart({ stats, loading }: { stats: OsvStatsResponse | null; loading: boolean }) {
  const data = stats?.monthly_trend ?? []

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <TrendingUp size={13} className="text-slate-400" />
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">月別 OSV 更新トレンド</span>
      </div>
      <div className="h-[160px]">
        {loading || data.length === 0 ? (
          <div className="h-full flex items-center justify-center text-xs text-slate-600">
            {loading ? '読み込み中...' : 'データなし'}
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis
                dataKey="year_month"
                tick={{ fill: '#475569', fontSize: 10 }}
                tickLine={false}
                axisLine={false}
                interval="preserveStartEnd"
              />
              <YAxis
                tick={{ fill: '#475569', fontSize: 10 }}
                tickLine={false}
                axisLine={false}
                allowDecimals={false}
              />
              <ReTooltip
                contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 12 }}
                formatter={(value) => [String(value) + ' 件', '件数']}
              />
              <Bar dataKey="count" fill="#7c3aed" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  )
}

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
        <SeverityPieChart stats={stats} loading={loading} />
        <EcosystemBarChart stats={stats} loading={loading} />
        <OsvMonthlyChart stats={stats} loading={loading} />
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
        <div className="flex gap-1">
          {SEVERITIES.map(sev => {
            const active = (sev === 'ALL' && severity === null) || sev === severity
            const cls = active
              ? sev === 'ALL'
                ? 'bg-slate-700 text-white'
                : (SEVERITY_CLS[sev] ?? 'bg-slate-700 text-white') + ' border'
              : 'bg-slate-800/50 text-slate-500 hover:text-slate-300'
            return (
              <button
                key={sev}
                onClick={() => handleSev(sev)}
                className={`px-2 py-1 rounded text-xs font-medium transition-colors ${cls}`}
              >
                {sev}
              </button>
            )
          })}
        </div>

        {/* キーワード検索 */}
        <div className="flex items-center gap-1.5 bg-slate-800/60 border border-slate-700 rounded-lg px-2.5 py-1.5 flex-1 min-w-[160px]">
          <Search size={11} className="text-slate-500 shrink-0" />
          <input
            type="text"
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(1) }}
            placeholder="OSV ID・パッケージ名・概要"
            className="bg-transparent text-xs text-slate-300 placeholder:text-slate-600 outline-none w-full"
          />
          {search && (
            <button onClick={clearSearch} className="text-slate-500 hover:text-slate-300">
              <X size={10} />
            </button>
          )}
        </div>

        {/* ソートセレクター */}
        <div className="flex items-center gap-1 bg-slate-800/60 border border-slate-700 rounded-lg px-2.5 py-1.5">
          <span className="text-[10px] text-slate-500 whitespace-nowrap">ソート:</span>
          <button
            onClick={() => { setSortBy('modified'); setPage(1) }}
            className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
              sortBy === 'modified' ? 'bg-violet-600 text-white' : 'text-slate-400 hover:text-slate-300'
            }`}
          >
            更新日
          </button>
          <button
            onClick={() => { setSortBy('cvss'); setPage(1) }}
            className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
              sortBy === 'cvss' ? 'bg-violet-600 text-white' : 'text-slate-400 hover:text-slate-300'
            }`}
          >
            CVSS
          </button>
        </div>
      </div>

      {/* ローディング */}
      {loading ? (
        <div className="space-y-2 py-4">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="flex items-center gap-3 py-2">
              <div className="h-4 w-16 bg-slate-800 rounded animate-pulse" />
              <div className="h-4 w-28 bg-slate-800 rounded animate-pulse" />
              <div className="h-4 w-16 bg-slate-800 rounded animate-pulse" />
              <div className="h-4 flex-1 bg-slate-800 rounded animate-pulse" />
            </div>
          ))}
        </div>

      /* データなし */
      ) : result && result.total === 0 ? (
        <div className="flex flex-col items-center justify-center gap-2 py-12 text-slate-600">
          <Shield size={28} />
          <p className="text-sm">該当する OSV 脆弱性はありません</p>
          <p className="text-xs text-slate-700">クローラーがデータを取得すると表示されます</p>
        </div>

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
                  <OsvRow key={`${item.osv_id}-${item.ecosystem}-${item.package_name}-${i}`} item={item} />
                ))}
              </tbody>
            </table>
          </div>

          {/* ページネーション */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between pt-2 border-t border-slate-800">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-sm text-slate-300 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <Loader2 size={0} />
                ← 前へ
              </button>
              <span className="text-sm text-slate-600 tabular-nums">
                {page} / {totalPages}
                <span className="ml-2 text-slate-700">（{result.total} 件）</span>
              </span>
              <button
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-sm text-slate-300 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
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
