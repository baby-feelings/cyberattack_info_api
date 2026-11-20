import { PanelFrame } from '../shared/PanelFrame'
import { LastFetched } from '../freshness/LastFetched'
import { SCREEN_FETCH_SOURCE } from '../freshness/freshnessConfig'
import { Package } from 'lucide-react'
import { TableLoadingSkeleton, EmptyState, Pagination } from '../shared/VulnPanelParts'
import { OperatingFilter } from '../shared/OperatingFilter'
import { RepoRail } from '../shared/RepoRail'
import { repoShortName } from '../shared/repoName'
import { DEPENDENCIES_TEXT as T } from './dependenciesConfig'
import { DependenciesSearchForm, DependenciesTable, RepoBadge } from './DependenciesSections'
import { useDependencies } from './useDependencies'

// 使っている画面（タブの中の小タブ）。取得は、表示されたときに始まる
export function DependenciesPanel({ authToken }: { authToken?: string }) {
  const d = useDependencies(authToken)
  const { filters, update } = d

  return (
    <PanelFrame
      label={T.label}
      icon={Package}
      onReload={d.reload}
      reloading={d.loading}
    >
      <p className="text-xs text-slate-500">{T.intro}</p>

      <LastFetched crawlerType={SCREEN_FETCH_SOURCE.dependencies} />

      <div className="flex flex-wrap items-center gap-3">
        <OperatingFilter value={filters.operating} onChange={d.handleOperating} />
      </div>

      <div className="flex flex-col md:flex-row gap-4">
        <RepoRail
          selected={filters.repo}
          onSelect={repo => update({ repo })}
          allBadge={
            <span className="text-slate-500 tabular-nums">
              {d.repos.reduce((n, r) => n + r.total, 0)}
            </span>
          }
          items={d.repos.map(r => ({
            key: r.repo_full_name,
            label: repoShortName(r.repo_full_name),
            muted: r.vulnerable === 0,
            badge: <RepoBadge stat={r} />,
          }))}
        />

        <div className="flex-1 min-w-0 flex flex-col gap-4">
          <DependenciesSearchForm
            packageText={d.packageText} onPackageText={d.setPackageText}
            versionText={d.versionText} onVersionText={d.setVersionText}
            ecosystem={filters.ecosystem} onEcosystem={ecosystem => update({ ecosystem })}
            vulnerableOnly={filters.vulnerableOnly}
            onToggleVulnerable={() => update({ vulnerableOnly: !filters.vulnerableOnly })}
            onSubmit={d.handleSubmit}
          />

          {d.loading ? (
            <TableLoadingSkeleton columnWidths={['w-48', 'w-40', 'w-24', 'w-24', 'flex-1']} />
          ) : d.failed ? (
            <EmptyState icon={<Package size={24} />} message={T.failed} />
          ) : d.items.length === 0 ? (
            <EmptyState
              icon={<Package size={24} />}
              message={filters.vulnerableOnly ? T.emptyVulnerable : T.empty}
            />
          ) : (
            <>
              <Pagination
                page={filters.page} totalPages={d.totalPages} total={d.total}
                onPageChange={d.changePage}
                position="top"
              />
              <DependenciesTable items={d.items} showRepo={!filters.repo} />
              <Pagination
                page={filters.page} totalPages={d.totalPages} total={d.total}
                onPageChange={d.changePage}
              />
            </>
          )}
        </div>
      </div>
    </PanelFrame>
  )
}
