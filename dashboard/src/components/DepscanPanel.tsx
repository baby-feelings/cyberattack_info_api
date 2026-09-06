import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Bug, RefreshCw, CheckCircle2, Sparkles,
} from 'lucide-react'
import {
  fetchAllDepscanFindings, fetchDepscanStats, fetchCrawlerLogs,
  type DependencyFindingOut, type DepscanStatsResponse,
} from '../api/client'
import {
  SeverityPieChart,
  TableLoadingSkeleton, EmptyState, Pagination,
  SeverityFilterButtons,
} from './shared/VulnPanelParts'
import { DepscanGroupRow } from './depscan/DepscanGroupRow'
import { RepoBarChart } from './depscan/RepoBarChart'
import {
  SEVERITY_CLS, SEVERITY_COLORS, ownerOf,
  groupFindings, groupBestSeverityRank, groupLatestDetectedAt,
} from './depscan/grouping'

const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const PER_PAGE = 30
// 新しいDEPSCANクロールが完了していないかを確認する間隔（ミリ秒）
const UPDATE_CHECK_INTERVAL_MS = 120000

// このパネルは常に GitHub ログイン済み状態（DepscanAuthGate配下）でのみ描画される。
// 認証は HttpOnly セッション Cookie 経由のため、サーバー側でログインユーザー本人が
// 所有するリポジトリのみに強制的に絞り込まれる（オーナーフィルターは実質不要になる）
export function DepscanPanel() {
  const [owner, setOwner] = useState<string | null>(null)
  const [severity, setSeverity] = useState<string | null>(null)
  const [showResolved, setShowResolved] = useState(false)
  const [page, setPage] = useState(1)
  const [findings, setFindings] = useState<DependencyFindingOut[]>([])
  const [stats, setStats] = useState<DepscanStatsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [newDataAvailable, setNewDataAvailable] = useState(false)
  // 表示中データの基準となる、最後に確認した最新クロールログID
  // （ポーリング用 effect から常に最新値を読めるよう state ではなく ref で持つ）
  const lastSeenLogIdRef = useRef<number | null>(null)

  // 直近成功した DEPSCAN クロールログの ID を取得する（取得失敗時は null）
  const fetchLatestLogId = useCallback(async (): Promise<number | null> => {
    try {
      const logs = await fetchCrawlerLogs({ crawlerType: 'DEPSCAN', status: 'success', limit: 1 })
      return logs[0]?.id ?? null
    } catch {
      return null
    }
  }, [])

  const load = useCallback(async (
    own: string | null, sev: string | null, resolved: boolean,
  ) => {
    setLoading(true)
    try {
      const [all, st] = await Promise.all([
        fetchAllDepscanFindings({
          owner: own, severity: sev, resolved: resolved ? null : false,
        }),
        fetchDepscanStats(),
      ])
      setFindings(all)
      setStats(st)
    } catch {
      // エラーは握りつぶし（データなし状態として扱う）
    } finally {
      setLoading(false)
    }
    // 表示したデータの基準として、この時点の最新クロールログIDを記録する
    lastSeenLogIdRef.current = await fetchLatestLogId()
    setNewDataAvailable(false)
  }, [fetchLatestLogId])

  useEffect(() => {
    load(owner, severity, showResolved)
  }, [load, owner, severity, showResolved])

  // 定期的に新しい DEPSCAN クロールが完了していないか確認し、あればバナーで通知する
  // （バックグラウンドで自動更新はせず、ユーザーが更新ボタンを押すまで表示は変えない）
  useEffect(() => {
    const interval = setInterval(async () => {
      const latestId = await fetchLatestLogId()
      if (
        latestId !== null
        && lastSeenLogIdRef.current !== null
        && latestId !== lastSeenLogIdRef.current
      ) {
        setNewDataAvailable(true)
      }
    }, UPDATE_CHECK_INTERVAL_MS)
    return () => clearInterval(interval)
  }, [fetchLatestLogId])

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

      {/* 新着データ通知バナー（自動更新はせず、ボタン押下で明示的に更新） */}
      {newDataAvailable && (
        <div className="flex items-center justify-between gap-3 rounded-lg border border-violet-500/30 bg-violet-500/10 px-3 py-2 text-xs text-violet-300">
          <span className="flex items-center gap-1.5">
            <Sparkles size={13} />
            新しいデータがあります
          </span>
          <button
            onClick={() => load(owner, severity, showResolved)}
            className="px-2.5 py-1 rounded-md bg-violet-600 hover:bg-violet-500 text-white font-medium transition-colors"
          >
            更新
          </button>
        </div>
      )}

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
