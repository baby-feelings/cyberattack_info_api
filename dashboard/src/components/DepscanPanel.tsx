import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Bug, ExternalLink, ChevronDown, ChevronUp,
  RefreshCw, CheckCircle2, BarChart2,
} from 'lucide-react'
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip as ReTooltip, XAxis, YAxis } from 'recharts'
import {
  fetchDepscanList, fetchDepscanStats,
  type DependencyFindingOut, type DepscanListResponse, type DepscanStatsResponse,
} from '../api/client'
import {
  SeverityBadge, ChartCard, SeverityPieChart,
  TableLoadingSkeleton, EmptyState, Pagination,
  SeverityFilterButtons,
} from './shared/VulnPanelParts'

// 深刻度バッジのスタイル（OSV と同じ CRITICAL/HIGH/MEDIUM/LOW 表記）
const SEVERITY_CLS: Record<string, string> = {
  CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/30',
  HIGH:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
  MEDIUM:   'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  LOW:      'bg-blue-500/15 text-blue-400 border-blue-500/30',
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#3b82f6',
  'N/A':    '#475569',
}

const REPO_CHART_COLORS = [
  '#7c3aed', '#0ea5e9', '#22d3ee', '#f59e0b',
  '#f43f5e', '#8b5cf6', '#f97316', '#6366f1',
]

const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const PER_PAGE = 30

// リポジトリ full_name（"owner/repo"）からオーナー名部分を取り出す
function ownerOf(repoFullName: string): string {
  return repoFullName.split('/')[0] ?? repoFullName
}

function DepscanRow({ item }: { item: DependencyFindingOut }) {
  const [open, setOpen] = useState(false)
  const detectedDate = new Date(item.detected_at).toLocaleDateString('ja-JP', {
    year: 'numeric', month: 'short', day: 'numeric',
  })

  return (
    <>
      <tr
        className="hover:bg-slate-800/40 transition-colors cursor-pointer"
        onClick={() => setOpen(o => !o)}
      >
        <td className="py-2.5 pr-3 w-20">
          <SeverityBadge severity={item.severity} classMap={SEVERITY_CLS} />
          {item.cvss_score != null && (
            <span className="block text-[10px] text-slate-600 mt-0.5 tabular-nums">
              {item.cvss_score.toFixed(1)}
            </span>
          )}
        </td>

        {/* リポジトリ */}
        <td className="py-2.5 pr-3 w-52">
          <a
            href={`https://github.com/${item.repo_full_name}`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-slate-300 hover:text-white text-xs transition-colors truncate max-w-[200px]"
            onClick={e => e.stopPropagation()}
          >
            {item.repo_full_name}
            <ExternalLink size={9} className="shrink-0" />
          </a>
          {item.resolved_at && (
            <span className="inline-flex items-center gap-0.5 mt-0.5 text-[10px] text-emerald-500">
              <CheckCircle2 size={9} /> 解決済み
            </span>
          )}
        </td>

        {/* パッケージ */}
        <td className="py-2.5 pr-3 w-40">
          <p className="text-slate-300 font-mono text-xs">{item.package_name}</p>
          <p className="text-slate-600 text-[10px] mt-0.5 font-mono">{item.installed_version}</p>
        </td>

        {/* 修正版 */}
        <td className="py-2.5 pr-3 w-32">
          {item.fixed_versions.length > 0 ? (
            <p className="text-emerald-500 text-[10px] font-mono">
              {item.fixed_versions[0]}
              {item.fixed_versions.length > 1 && ` +${item.fixed_versions.length - 1}`}
            </p>
          ) : (
            <span className="text-slate-700 text-xs">未提供</span>
          )}
        </td>

        {/* 概要 */}
        <td className="py-2.5 pr-3">
          <p className="text-slate-400 text-xs truncate max-w-[240px]">{item.summary}</p>
        </td>

        <td className="py-2.5 text-xs text-slate-600 tabular-nums whitespace-nowrap w-24">
          {detectedDate}
        </td>

        <td className="py-2.5 pl-2 text-right w-5">
          {open
            ? <ChevronUp size={12} className="text-slate-500 ml-auto" />
            : <ChevronDown size={12} className="text-slate-500 ml-auto" />}
        </td>
      </tr>

      {/* 展開: 詳細・修正バージョン全件・ロックファイルパス・OSVリンク */}
      {open && (
        <tr className="bg-slate-800/30">
          <td colSpan={7} className="px-4 py-3 text-xs text-slate-400 space-y-2">
            {item.summary && (
              <p className="leading-relaxed whitespace-pre-wrap">{item.summary}</p>
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
            <p className="flex items-center gap-1.5">
              <span className="text-slate-500">ロックファイル:</span>
              <span className="font-mono text-[10px] text-slate-400">{item.manifest_path}</span>
            </p>
            <a
              href={`https://osv.dev/vulnerability/${item.osv_id}`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-violet-400 hover:text-violet-300 underline underline-offset-2 text-[10px]"
            >
              {item.osv_id} を OSV.dev で確認
              <ExternalLink size={9} />
            </a>
          </td>
        </tr>
      )}
    </>
  )
}

// リポジトリ別件数の棒グラフ（上位8件）
function RepoBarChart({ stats, loading }: { stats: DepscanStatsResponse | null; loading: boolean }) {
  const data = (stats?.repos ?? []).slice(0, 8).map(r => ({
    // "owner/repo" だとラベルが長くなるため repo 名のみ表示
    name: r.repo_full_name.split('/')[1] ?? r.repo_full_name,
    count: r.count,
  }))

  return (
    <ChartCard
      icon={<BarChart2 size={13} className="text-slate-400" />}
      title="リポジトリ別件数（未解決）"
      loading={loading}
      isEmpty={data.length === 0}
      height={160}
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
          <XAxis
            dataKey="name"
            tick={{ fill: '#475569', fontSize: 9 }}
            tickLine={false}
            axisLine={false}
            interval={0}
            angle={-30}
            textAnchor="end"
            height={40}
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
              <Cell key={`cell-${index}`} fill={REPO_CHART_COLORS[index % REPO_CHART_COLORS.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  )
}

export function DepscanPanel() {
  const [owner, setOwner] = useState<string | null>(null)
  const [severity, setSeverity] = useState<string | null>(null)
  const [showResolved, setShowResolved] = useState(false)
  const [page, setPage] = useState(1)
  const [result, setResult] = useState<DepscanListResponse | null>(null)
  const [stats, setStats] = useState<DepscanStatsResponse | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async (
    own: string | null, sev: string | null, resolved: boolean, p: number,
  ) => {
    setLoading(true)
    try {
      const [list, st] = await Promise.all([
        fetchDepscanList({
          owner: own, severity: sev, page: p, perPage: PER_PAGE,
          resolved: resolved ? null : false,
        }),
        fetchDepscanStats(),
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
    load(owner, severity, showResolved, page)
  }, [load, owner, severity, showResolved, page])

  // オーナー一覧は stats.repos（未解決分の全リポジトリ）から動的に導出する。
  // 表示されるのは DB に保存済み＝DEPSCAN が GITHUB_TOKEN の権限内で実際に
  // スキャンしたリポジトリのみ（現状は GITHUB_USERNAME=baby-feelings が
  // 所有するリポジトリだけ）。運用者が意図的に監視対象アカウントを増やした
  // 場合のみボタンが増える設計で、無関係な第三者のデータが混ざることはない。
  const owners = useMemo(() => {
    const set = new Set((stats?.repos ?? []).map(r => ownerOf(r.repo_full_name)))
    return Array.from(set).sort()
  }, [stats])

  function handleOwner(o: string) {
    setOwner(o === 'ALL' ? null : o)
    setPage(1)
  }

  function handleSev(sev: string) {
    setSeverity(sev === 'ALL' ? null : sev)
    setPage(1)
  }

  const totalPages = result ? Math.ceil(result.total / PER_PAGE) : 0

  const critCount = stats?.severities.find(s => s.severity === 'CRITICAL')?.count ?? 0
  const highCount = stats?.severities.find(s => s.severity === 'HIGH')?.count ?? 0

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg flex flex-col gap-5">

      {/* ヘッダー */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Bug size={16} className="text-slate-400" />
          <span className="text-sm font-semibold text-slate-400 uppercase tracking-wider">
            自作アプリの依存ライブラリ脆弱性（未解決）
          </span>
        </div>
        <div className="flex items-center gap-3">
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
            onClick={() => load(owner, severity, showResolved, page)}
            disabled={loading}
            className="text-slate-500 hover:text-slate-300 transition-colors disabled:opacity-40 p-1 rounded"
            title="再読み込み"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* ビジュアライゼーション: 重要度別グラフ・リポジトリ別件数 */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <SeverityPieChart
          icon={<Bug size={13} className="text-slate-400" />}
          data={stats?.severities ?? []}
          colorMap={SEVERITY_COLORS}
          loading={loading}
        />
        <RepoBarChart stats={stats} loading={loading} />
      </div>

      {/* オーナーフィルター */}
      {owners.length > 1 && (
        <div className="flex flex-wrap gap-1.5">
          {['ALL', ...owners].map(o => {
            const active = (o === 'ALL' && owner === null) || o === owner
            return (
              <button
                key={o}
                onClick={() => handleOwner(o)}
                className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors ${
                  active
                    ? 'bg-violet-600 text-white shadow'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-300 hover:bg-slate-700'
                }`}
              >
                {o}
              </button>
            )
          })}
        </div>
      )}

      {/* 重要度フィルター + 解決済み表示切替 */}
      <div className="flex flex-wrap items-center gap-3">
        <SeverityFilterButtons
          severities={SEVERITIES}
          active={severity}
          onSelect={handleSev}
          classMap={SEVERITY_CLS}
        />

        <button
          onClick={() => { setShowResolved(v => !v); setPage(1) }}
          className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
            showResolved
              ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
              : 'bg-slate-800/60 text-slate-500 border-slate-700 hover:text-slate-300'
          }`}
        >
          <CheckCircle2 size={12} />
          解決済みを含む
        </button>
      </div>

      {/* ローディング */}
      {loading ? (
        <TableLoadingSkeleton columnWidths={['w-16', 'w-40', 'w-28', 'flex-1']} />

      /* データなし */
      ) : result && result.total === 0 ? (
        <EmptyState icon={<Bug size={28} />} message="該当する依存ライブラリ脆弱性はありません" />

      /* テーブル */
      ) : result && (
        <>
          <div className="overflow-x-auto -mx-1 px-1">
            <table className="w-full text-sm min-w-[760px]">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-20">深刻度</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-52">リポジトリ</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-40">パッケージ</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-32">修正版</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3">概要</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-24">検知日</th>
                  <th className="w-5" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {result.data.map((item, i) => (
                  <DepscanRow
                    key={`${item.repo_full_name}-${item.package_name}-${item.osv_id}-${i}`}
                    item={item}
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
