import { Bug } from 'lucide-react'
import {
  SeverityPieChart,
  TableLoadingSkeleton, EmptyState, Pagination,
  SeverityFilterButtons,
} from './shared/VulnPanelParts'
import { RepoBarChart } from './depscan/RepoBarChart'
import { SEVERITY_CLS, SEVERITY_COLORS } from './depscan/grouping'
import { useDepscanData } from './depscan/useDepscanData'
import { OperatingFilter } from './shared/OperatingFilter'
import { ExceptedToggle } from './shared/ExceptedToggle'
import { ActionSummary } from './shared/ActionSummary'
import { CollapsibleSection } from './shared/CollapsibleSection'
import { RepoRail } from './shared/RepoRail'
import { repoShortName } from './shared/repoName'
import { DepscanSortSelector } from './depscan/DepscanSortSelector'
import { DEPSCAN_TEXT as T, SEVERITIES } from './depscan/depscanPanelConfig'
import {
  DepscanHeader, DepscanTable, NewDataBanner, OwnerFilter, RepoBadge, ResolvedToggle,
} from './depscan/DepscanSections'

// authToken 指定時（GitHubログイン経由）は、サーバー側でログインユーザー本人が
// 所有するリポジトリのみに強制的に絞り込まれる（オーナーフィルターは実質不要になる）
export function DepscanPanel({ authToken }: { authToken?: string } = {}) {
  const {
    owner, severity, showResolved, showExcepted, operating, sortBy, handleSort, page, setPage,
    stats, loading, newDataAvailable,
    load, handleOwner, handleSev, handleOperating, toggleShowResolved, toggleShowExcepted,
    owners, groups, totalPages, pageGroups, critCount, highCount,
    repos, activeRepo, handleRepo,
  } = useDepscanData(authToken)

  const actionable = critCount + highCount
  // 現在の絞り込み条件で取り直す（新着の更新・再読み込み・例外の変更後に使う）
  const reload = () => load(owner, severity, showResolved, operating, showExcepted)

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-lg flex flex-col gap-5">
      {newDataAvailable && <NewDataBanner onRefresh={reload} />}

      <DepscanHeader loading={loading} onReload={reload} />

      {/* グラフ。最初は表示し、見出しを押すと閉じられる */}
      <CollapsibleSection summary={T.charts}>
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
        <OwnerFilter owners={owners} owner={owner} onSelect={handleOwner} />
        <SeverityFilterButtons
          severities={SEVERITIES}
          active={severity}
          onSelect={handleSev}
          classMap={SEVERITY_CLS}
        />
        <ResolvedToggle active={showResolved} onToggle={toggleShowResolved} />
        <ExceptedToggle active={showExcepted} onToggle={toggleShowExcepted} />
        <DepscanSortSelector value={sortBy} onChange={handleSort} />
      </div>

      {/* いま対応が必要な件数（未解決の CRITICAL・HIGH） */}
      <ActionSummary
        count={actionable}
        criteria={T.actionCriteria}
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
          {loading ? (
            <TableLoadingSkeleton columnWidths={['w-16', 'w-40', 'w-28', 'flex-1']} />
          ) : groups.length === 0 ? (
            <EmptyState icon={<Bug size={28} />} message={T.empty} />
          ) : (
            <>
              <Pagination page={page} totalPages={totalPages} total={groups.length} onPageChange={setPage} position="top" />
              <DepscanTable
                pageGroups={pageGroups} sortBy={sortBy} activeRepo={activeRepo}
                authToken={authToken} onExceptionChanged={reload}
              />
              <Pagination page={page} totalPages={totalPages} total={groups.length} onPageChange={setPage} />
            </>
          )}
        </div>
      </div>
    </div>
  )
}
