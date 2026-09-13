import { useState } from 'react'
import {
  Bug, RefreshCw, CheckCircle2, Sparkles, GitPullRequest,
} from 'lucide-react'
import {
  SeverityPieChart,
  TableLoadingSkeleton, EmptyState, Pagination,
  SeverityFilterButtons,
} from './shared/VulnPanelParts'
import { DepscanGroupRow } from './depscan/DepscanGroupRow'
import { RepoBarChart } from './depscan/RepoBarChart'
import { DependabotOpsModal } from './depscan/DependabotOpsModal'
import { SEVERITY_CLS, SEVERITY_COLORS } from './depscan/grouping'
import { useDepscanData } from './depscan/useDepscanData'

const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

// authToken 指定時（GitHubログイン経由）は、サーバー側でログインユーザー本人が
// 所有するリポジトリのみに強制的に絞り込まれる（オーナーフィルターは実質不要になる）
export function DepscanPanel({ authToken }: { authToken?: string } = {}) {
  const [depsOpsOpen, setDepsOpsOpen] = useState(false)

  const {
    owner, severity, showResolved, page, setPage,
    stats, loading, newDataAvailable,
    load, handleOwner, handleSev, toggleShowResolved,
    owners, groups, totalPages, pageGroups, critCount, highCount,
  } = useDepscanData(authToken)

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
            onClick={() => setDepsOpsOpen(true)}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-700 transition-colors"
          >
            <GitPullRequest size={13} />
            Dependabot運用状況
          </button>
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
          onClick={toggleShowResolved}
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
                  <th className="text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3 w-24">到達可能性</th>
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

      {/* Dependabot PR 自動運用（DEPSOPS）の判定履歴。専用タブは作らず全画面モーダルで表示する */}
      <DependabotOpsModal open={depsOpsOpen} onClose={() => setDepsOpsOpen(false)} />
    </div>
  )
}
