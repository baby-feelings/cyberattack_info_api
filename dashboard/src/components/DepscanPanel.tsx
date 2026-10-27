import { useState } from 'react'
import {
  Bug, RefreshCw, CheckCircle2, Sparkles, GitPullRequest, Package,
} from 'lucide-react'
import {
  SeverityPieChart,
  TableLoadingSkeleton, EmptyState, Pagination,
  SeverityFilterButtons,
} from './shared/VulnPanelParts'
import { DepscanGroupRow } from './depscan/DepscanGroupRow'
import { RepoBarChart } from './depscan/RepoBarChart'
import { DependabotOpsModal } from './depscan/DependabotOpsModal'
import { DependenciesModal } from './depscan/DependenciesModal'
import { SEVERITY_CLS, SEVERITY_COLORS } from './depscan/grouping'
import { useDepscanData } from './depscan/useDepscanData'
import { OperatingFilter } from './shared/OperatingFilter'
import { ActionSummary } from './shared/ActionSummary'
import { CollapsibleSection } from './shared/CollapsibleSection'
import { RepoRail } from './shared/RepoRail'
import { repoShortName } from './shared/repoName'

const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

const TH = 'text-left text-xs font-semibold text-slate-600 uppercase tracking-wider pb-2 pr-3'

// 左のアプリ一覧に出す件数バッジ。対応が必要な件数（CRITICAL・HIGH）を目立たせ、
// 無いアプリは薄い数字（総件数）にする
function RepoBadge({ crit, high, total }: { crit: number; high: number; total: number }) {
  if (crit + high === 0) return <span className="text-slate-500 tabular-nums">{total}</span>
  return (
    <span className="flex items-center gap-1 tabular-nums">
      {crit > 0 && (
        <span className="px-1.5 rounded-full bg-red-500/15 text-red-400 font-semibold" title="CRITICAL">{crit}</span>
      )}
      {high > 0 && (
        <span className="px-1.5 rounded-full bg-orange-500/15 text-orange-400 font-semibold" title="HIGH">{high}</span>
      )}
    </span>
  )
}

// authToken 指定時（GitHubログイン経由）は、サーバー側でログインユーザー本人が
// 所有するリポジトリのみに強制的に絞り込まれる（オーナーフィルターは実質不要になる）
export function DepscanPanel({ authToken }: { authToken?: string } = {}) {
  const [depsOpsOpen, setDepsOpsOpen] = useState(false)
  const [searchOpen, setSearchOpen] = useState(false)

  const {
    owner, severity, showResolved, operating, page, setPage,
    stats, loading, newDataAvailable,
    load, handleOwner, handleSev, handleOperating, toggleShowResolved,
    owners, groups, totalPages, pageGroups, critCount, highCount,
    repos, activeRepo, handleRepo,
  } = useDepscanData(authToken)

  const actionable = critCount + highCount

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
            onClick={() => load(owner, severity, showResolved, operating)}
            className="px-2.5 py-1 rounded-md bg-violet-600 hover:bg-violet-500 text-white font-medium transition-colors"
          >
            更新
          </button>
        </div>
      )}

      {/* ヘッダー */}
      {/* 1段目: タイトルと再読み込み／2段目: 操作ボタン。幅が足りなければボタン単位で折り返す
          （1行に詰めると、スマホ幅でボタンの文字が縦に折り返されて崩れる） */}
      <div className="flex flex-col gap-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-center gap-2 min-w-0">
            <Bug size={16} className="text-slate-400 shrink-0" />
            <span className="text-sm font-semibold text-slate-400 uppercase tracking-wider">
              自作アプリの依存ライブラリ脆弱性（未解決）
            </span>
          </div>
          <button
            onClick={() => load(owner, severity, showResolved, operating)}
            disabled={loading}
            className="shrink-0 text-slate-500 hover:text-slate-300 transition-colors disabled:opacity-40 p-1 rounded"
            title="再読み込み"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => setSearchOpen(true)}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium whitespace-nowrap bg-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-700 transition-colors"
          >
            <Package size={13} />
            依存パッケージ
          </button>
          <button
            onClick={() => setDepsOpsOpen(true)}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium whitespace-nowrap bg-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-700 transition-colors"
          >
            <GitPullRequest size={13} />
            Dependabot運用状況
          </button>
        </div>
      </div>

      {/* グラフ。最初は表示し、見出しを押すと閉じられる */}
      <CollapsibleSection summary="グラフ（重要度別・リポジトリ別）">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <SeverityPieChart
            icon={<Bug size={13} className="text-slate-400" />}
            data={stats?.severities ?? []}
            colorMap={SEVERITY_COLORS}
            loading={loading}
          />
          <RepoBarChart stats={stats} loading={loading} />
        </div>
      </CollapsibleSection>

      {/* 運用状態フィルター + オーナーフィルター + 重要度フィルター + 解決済み表示切替 */}
      <div className="flex flex-wrap items-center gap-3">
        <OperatingFilter value={operating} onChange={handleOperating} />
        {owners.length > 1 && (
          <div role="group" aria-label="オーナーフィルター" className="flex flex-wrap gap-1.5">
            {['ALL', ...owners].map(o => {
              const active = (o === 'ALL' && owner === null) || o === owner
              return (
                <button
                  key={o}
                  onClick={() => handleOwner(o)}
                  aria-pressed={active}
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
        <SeverityFilterButtons
          severities={SEVERITIES}
          active={severity}
          onSelect={handleSev}
          classMap={SEVERITY_CLS}
        />
        <button
          onClick={toggleShowResolved}
          aria-pressed={showResolved}
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

      {/* いま対応が必要な件数（未解決の CRITICAL・HIGH） */}
      <ActionSummary
        count={actionable}
        criteria="CRITICAL・HIGH"
        total={stats?.total ?? null}
        loading={loading && !stats}
      />

      {/* 左: アプリ一覧（対応が必要なアプリが上）／右: 選んだアプリの脆弱性 */}
      <div className="flex flex-col md:flex-row gap-4">
        <RepoRail
          selected={activeRepo}
          onSelect={handleRepo}
          allBadge={<span className="text-slate-500 tabular-nums">{repos.reduce((n, r) => n + r.total, 0)}</span>}
          items={repos.map(r => ({
            key: r.repo,
            label: repoShortName(r.repo),
            muted: r.crit + r.high === 0,
            badge: <RepoBadge crit={r.crit} high={r.high} total={r.total} />,
          }))}
        />

        <div className="flex-1 min-w-0 flex flex-col gap-3">
          {/* ローディング */}
          {loading ? (
            <TableLoadingSkeleton columnWidths={['w-16', 'w-40', 'w-28', 'flex-1']} />

          /* データなし */
          ) : groups.length === 0 ? (
            <EmptyState icon={<Bug size={28} />} message="該当する依存ライブラリ脆弱性はありません" />

          /* テーブル（パッケージ単位に集約） */
          ) : (
            <>
              <Pagination page={page} totalPages={totalPages} total={groups.length} onPageChange={setPage} position="top" />

              <div className="overflow-x-auto -mx-1 px-1">
                <table aria-label="依存ライブラリ脆弱性一覧" className="w-full text-sm min-w-[560px]">
                  <thead>
                    <tr className="border-b border-slate-800">
                      <th className={`${TH} w-24`}>深刻度</th>
                      {!activeRepo && <th className={`${TH} w-52`}>リポジトリ</th>}
                      <th className={`${TH} w-40`}>パッケージ</th>
                      <th className={`${TH} w-32`}>修正版</th>
                      <th className={`${TH} w-28`}>到達可能性</th>
                      <th className={`${TH} w-24`}>検知日</th>
                      <th className="w-5" />
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {pageGroups.map((group, i) => (
                      <DepscanGroupRow
                        key={`${group.repo_full_name}-${group.package_name}-${group.installed_version}-${i}`}
                        group={group}
                        showRepo={!activeRepo}
                      />
                    ))}
                  </tbody>
                </table>
              </div>

              <Pagination page={page} totalPages={totalPages} total={groups.length} onPageChange={setPage} />
            </>
          )}
        </div>
      </div>


      {/* Dependabot PR 自動運用（DEPSOPS）の判定履歴。専用タブは作らず全画面モーダルで表示する */}
      <DependabotOpsModal open={depsOpsOpen} onClose={() => setDepsOpsOpen(false)} />

      {/* 使っている依存パッケージの閲覧・検索（アプリごとの一覧／新しい脆弱性の影響範囲の確認）。同じく全画面モーダル */}
      <DependenciesModal open={searchOpen} onClose={() => setSearchOpen(false)} authToken={authToken} />
    </div>
  )
}
