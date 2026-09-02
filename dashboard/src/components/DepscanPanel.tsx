import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Bug, ExternalLink, ChevronDown, ChevronUp,
  RefreshCw, CheckCircle2, BarChart2,
} from 'lucide-react'
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip as ReTooltip, XAxis, YAxis } from 'recharts'
import {
  fetchAllDepscanFindings, fetchDepscanStats,
  type DependencyFindingOut, type DepscanStatsResponse,
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

const SEVERITY_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

function severityRank(severity: string | null): number {
  return SEVERITY_ORDER[severity ?? ''] ?? 4
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

// サーバーは「パッケージ×CVE」単位で1件返すため、同一パッケージ・同一バージョンの
// 複数CVEを1グループに集約する（Slack通知・GitHub Issue自動起票と同じ考え方）。
interface FindingGroup {
  repo_full_name: string
  package_name: string
  installed_version: string
  findings: DependencyFindingOut[]
}

function groupFindings(data: DependencyFindingOut[]): FindingGroup[] {
  const map = new Map<string, FindingGroup>()
  for (const f of data) {
    const key = `${f.repo_full_name}|${f.package_name}|${f.installed_version}`
    let g = map.get(key)
    if (!g) {
      g = {
        repo_full_name: f.repo_full_name,
        package_name: f.package_name,
        installed_version: f.installed_version,
        findings: [],
      }
      map.set(key, g)
    }
    g.findings.push(f)
  }
  return Array.from(map.values())
}

function groupBestSeverityRank(g: FindingGroup): number {
  return Math.min(...g.findings.map(f => severityRank(f.severity)))
}

function groupLatestDetectedAt(g: FindingGroup): string {
  return g.findings.reduce((max, f) => (f.detected_at > max ? f.detected_at : max), g.findings[0].detected_at)
}

function groupIsResolved(g: FindingGroup): boolean {
  return g.findings.every(f => f.resolved_at)
}

function groupFixedVersions(g: FindingGroup): string[] {
  const set = new Set<string>()
  for (const f of g.findings) {
    for (const v of f.fixed_versions) set.add(v)
  }
  return Array.from(set).sort()
}

function groupSeverityCounts(g: FindingGroup): [string, number][] {
  const counts = new Map<string, number>()
  for (const f of g.findings) {
    const sev = f.severity ?? 'N/A'
    counts.set(sev, (counts.get(sev) ?? 0) + 1)
  }
  return Array.from(counts.entries()).sort(
    (a, b) => severityRank(a[0] === 'N/A' ? null : a[0]) - severityRank(b[0] === 'N/A' ? null : b[0]),
  )
}

function DepscanGroupRow({ group }: { group: FindingGroup }) {
  const [open, setOpen] = useState(false)
  const bestSeverity = group.findings
    .slice()
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))[0].severity
  const fixedVersions = groupFixedVersions(group)
  const severityCounts = groupSeverityCounts(group)
  const latestDate = new Date(groupLatestDetectedAt(group)).toLocaleDateString('ja-JP', {
    year: 'numeric', month: 'short', day: 'numeric',
  })

  return (
    <>
      <tr
        className="hover:bg-slate-800/40 transition-colors cursor-pointer"
        onClick={() => setOpen(o => !o)}
      >
        <td className="py-2.5 pr-3 w-20">
          <SeverityBadge severity={bestSeverity} classMap={SEVERITY_CLS} />
          <span className="block text-[10px] text-slate-600 mt-0.5 tabular-nums">
            計{group.findings.length}件
          </span>
        </td>

        {/* リポジトリ */}
        <td className="py-2.5 pr-3 w-52">
          <a
            href={`https://github.com/${group.repo_full_name}`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-slate-300 hover:text-white text-xs transition-colors truncate max-w-[200px]"
            onClick={e => e.stopPropagation()}
          >
            {group.repo_full_name}
            <ExternalLink size={9} className="shrink-0" />
          </a>
          {groupIsResolved(group) && (
            <span className="inline-flex items-center gap-0.5 mt-0.5 text-[10px] text-emerald-500">
              <CheckCircle2 size={9} /> 解決済み
            </span>
          )}
        </td>

        {/* パッケージ */}
        <td className="py-2.5 pr-3 w-40">
          <p className="text-slate-300 font-mono text-xs">{group.package_name}</p>
          <p className="text-slate-600 text-[10px] mt-0.5 font-mono">{group.installed_version}</p>
        </td>

        {/* 修正版 */}
        <td className="py-2.5 pr-3 w-32">
          {fixedVersions.length > 0 ? (
            <p className="text-emerald-500 text-[10px] font-mono">
              {fixedVersions[0]}
              {fixedVersions.length > 1 && ` +${fixedVersions.length - 1}`}
            </p>
          ) : (
            <span className="text-slate-700 text-xs">未提供</span>
          )}
        </td>

        {/* 重大度内訳 */}
        <td className="py-2.5 pr-3">
          <div className="flex flex-wrap gap-1">
            {severityCounts.map(([sev, count]) => (
              <span
                key={sev}
                className={`px-1.5 py-0.5 rounded text-[10px] font-medium border ${
                  SEVERITY_CLS[sev] ?? 'bg-slate-800 text-slate-500 border-slate-700'
                }`}
              >
                {sev}×{count}
              </span>
            ))}
          </div>
        </td>

        <td className="py-2.5 text-xs text-slate-600 tabular-nums whitespace-nowrap w-24">
          {latestDate}
        </td>

        <td className="py-2.5 pl-2 text-right w-5">
          {open
            ? <ChevronUp size={12} className="text-slate-500 ml-auto" />
            : <ChevronDown size={12} className="text-slate-500 ml-auto" />}
        </td>
      </tr>

      {/* 展開: 個々のCVE一覧 */}
      {open && (
        <tr className="bg-slate-800/30">
          <td colSpan={7} className="px-4 py-3 text-xs text-slate-400">
            <p className="text-slate-500 mb-2">
              ロックファイル: <span className="font-mono text-slate-400">{group.findings[0].manifest_path}</span>
            </p>
            <div className="space-y-2.5">
              {group.findings
                .slice()
                .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
                .map(f => (
                  <div key={f.osv_id} className="flex flex-col gap-1 border-l-2 border-slate-700 pl-2.5">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={f.severity} classMap={SEVERITY_CLS} />
                      {f.cvss_score != null && (
                        <span className="text-[10px] text-slate-600 tabular-nums">{f.cvss_score.toFixed(1)}</span>
                      )}
                      <a
                        href={`https://osv.dev/vulnerability/${f.osv_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-violet-400 hover:text-violet-300 font-mono text-[10px]"
                      >
                        {f.osv_id}
                        <ExternalLink size={8} />
                      </a>
                    </div>
                    <p className="leading-relaxed">{f.summary}</p>
                    {f.fixed_versions.length > 0 && (
                      <p className="flex flex-wrap items-center gap-1">
                        <span className="text-slate-500">修正版:</span>
                        {f.fixed_versions.map(v => (
                          <span key={v} className="text-emerald-500 font-mono text-[10px]">{v}</span>
                        ))}
                      </p>
                    )}
                  </div>
                ))}
            </div>
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
  const [findings, setFindings] = useState<DependencyFindingOut[]>([])
  const [stats, setStats] = useState<DepscanStatsResponse | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async (
    own: string | null, sev: string | null, resolved: boolean,
  ) => {
    setLoading(true)
    try {
      const [all, st] = await Promise.all([
        fetchAllDepscanFindings({ owner: own, severity: sev, resolved: resolved ? null : false }),
        fetchDepscanStats(),
      ])
      setFindings(all)
      setStats(st)
    } catch {
      // エラーは握りつぶし（データなし状態として扱う）
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load(owner, severity, showResolved)
  }, [load, owner, severity, showResolved])

  // オーナー一覧は stats.repos（未解決分の全リポジトリ）から動的に導出する。
  // 表示されるのは DB に保存済み＝DEPSCAN が GITHUB_TOKEN の権限内で実際に
  // スキャンしたリポジトリのみ（現状は GITHUB_USERNAME=baby-feelings が
  // 所有するリポジトリだけ）。運用者が意図的に監視対象アカウントを増やした
  // 場合のみボタンが増える設計で、無関係な第三者のデータが混ざることはない。
  const owners = useMemo(() => {
    const set = new Set((stats?.repos ?? []).map(r => ownerOf(r.repo_full_name)))
    return Array.from(set).sort()
  }, [stats])

  // パッケージ×バージョン単位に集約し、重大度が高い順・検知が新しい順に並べる
  const groups = useMemo(() => {
    const g = groupFindings(findings)
    g.sort((a, b) => {
      const r = groupBestSeverityRank(a) - groupBestSeverityRank(b)
      if (r !== 0) return r
      return groupLatestDetectedAt(b).localeCompare(groupLatestDetectedAt(a))
    })
    return g
  }, [findings])

  function handleOwner(o: string) {
    setOwner(o === 'ALL' ? null : o)
    setPage(1)
  }

  function handleSev(sev: string) {
    setSeverity(sev === 'ALL' ? null : sev)
    setPage(1)
  }

  const totalPages = Math.ceil(groups.length / PER_PAGE)
  const pageGroups = groups.slice((page - 1) * PER_PAGE, page * PER_PAGE)

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
              <span className="text-slate-500">/ {stats.total} 件（{groups.length} パッケージ）</span>
            </div>
          )}
          <button
            onClick={() => load(owner, severity, showResolved)}
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
      ) : groups.length === 0 ? (
        <EmptyState icon={<Bug size={28} />} message="該当する依存ライブラリ脆弱性はありません" />

      /* テーブル（パッケージ単位に集約） */
      ) : (
        <>
          <div className="overflow-x-auto -mx-1 px-1">
            <table className="w-full text-sm min-w-[760px]">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-20">深刻度</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-52">リポジトリ</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-40">パッケージ</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-32">修正版</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3">重大度内訳</th>
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-24">検知日</th>
                  <th className="w-5" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {pageGroups.map((group, i) => (
                  <DepscanGroupRow
                    key={`${group.repo_full_name}-${group.package_name}-${group.installed_version}-${i}`}
                    group={group}
                  />
                ))}
              </tbody>
            </table>
          </div>

          <Pagination page={page} totalPages={totalPages} total={groups.length} onPageChange={setPage} />
        </>
      )}
    </div>
  )
}
