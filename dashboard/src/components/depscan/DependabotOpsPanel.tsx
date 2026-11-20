import { PanelFrame } from '../shared/PanelFrame'
import { LastFetched } from '../freshness/LastFetched'
import { SCREEN_FETCH_SOURCE } from '../freshness/freshnessConfig'
import { GitPullRequest } from 'lucide-react'
import { TableLoadingSkeleton, EmptyState, Pagination } from '../shared/VulnPanelParts'
import { OperatingFilter } from '../shared/OperatingFilter'
import { DepsOpsRepoBarChart } from './DepsOpsRepoBarChart'
import { DEPSOPS_TEXT as T } from './dependabotOpsConfig'
import { ActionFilterButtons, DependabotOpsTable } from './DependabotOpsSections'
import { useDependabotOps } from './useDependabotOps'

// Dependabot PR 自動運用（DEPSOPS）の判定履歴を表示する画面（「依存ライブラリ」タブの小タブ）。
export function DependabotOpsPanel() {
  const d = useDependabotOps()

  return (
    <PanelFrame
      label={T.label} title={T.title}
      icon={GitPullRequest} maxWidth="max-w-5xl"
      onReload={d.reload} reloading={d.loading || d.statsLoading}
    >
      <LastFetched crawlerType={SCREEN_FETCH_SOURCE.depsops} />

      <DepsOpsRepoBarChart stats={d.repoStats} loading={d.statsLoading} />

      <div className="flex flex-wrap items-center gap-3">
        <OperatingFilter value={d.operating} onChange={d.handleOperating} />
      </div>

      <ActionFilterButtons action={d.action} onChange={d.handleAction} />

      {d.loading ? (
        <TableLoadingSkeleton columnWidths={['w-40', 'w-24', 'w-16', 'flex-1', 'w-24']} />
      ) : d.items.length === 0 ? (
        <EmptyState icon={<GitPullRequest size={24} />} message={T.empty} />
      ) : (
        <>
          <Pagination page={d.page} totalPages={d.totalPages} total={d.total} onPageChange={d.setPage} position="top" />
          <DependabotOpsTable items={d.items} />
          <Pagination page={d.page} totalPages={d.totalPages} total={d.total} onPageChange={d.setPage} />
        </>
      )}
    </PanelFrame>
  )
}
