import { PanelFrame } from '../shared/PanelFrame'
import { LastFetched } from '../freshness/LastFetched'
import { SCREEN_FETCH_SOURCE } from '../freshness/freshnessConfig'
import { Cpu, AlertTriangle } from 'lucide-react'
import { TableLoadingSkeleton, EmptyState } from '../shared/VulnPanelParts'
import { OperatingFilter } from '../shared/OperatingFilter'
import { RepoRail } from '../shared/RepoRail'
import { repoShortName } from '../shared/repoName'
import { INPUT_CLS, RUNTIMES_TEXT, RUNTIME_OPTIONS, TH } from './runtimesConfig'
import { EolCell, NewerSeriesNote, RecommendedStrip, RepoBadge, StateBadge } from './RuntimesSections'
import { useRuntimes } from './useRuntimes'

// 使っている画面（タブの中の小タブ）。取得は、表示されたときに始まる
export function RuntimesPanel({ authToken }: { authToken?: string }) {
  const { filters, update, handleOperating, loading, failed, items, repos, releases } = useRuntimes(authToken)

  return (
    <PanelFrame
      label={RUNTIMES_TEXT.label}
      icon={Cpu}
    >
      <p className="text-xs text-slate-500">{RUNTIMES_TEXT.intro}</p>

      {/* 言語・実行環境の情報を最後に取得した日時 */}
      <LastFetched crawlerType={SCREEN_FETCH_SOURCE.runtimes} />

      <RecommendedStrip releases={releases} />
      <NewerSeriesNote releases={releases} />

      <div className="flex flex-wrap items-center gap-3">
        <OperatingFilter value={filters.operating} onChange={handleOperating} />
      </div>

      <div className="flex flex-col md:flex-row gap-4">
        <RepoRail
          selected={filters.repo}
          onSelect={repo => update({ repo })}
          allBadge={
            <span className="text-slate-500 tabular-nums">
              {repos.reduce((n, r) => n + r.total, 0)}
            </span>
          }
          items={repos.map(r => ({
            key: r.repo_full_name,
            label: repoShortName(r.repo_full_name),
            muted: r.needs_action === 0,
            badge: <RepoBadge stat={r} />,
          }))}
        />

        <div className="flex-1 min-w-0 flex flex-col gap-4">
          <div className="flex flex-wrap items-end gap-3">
            <label className="flex flex-col gap-1 text-xs text-slate-400">
              {RUNTIMES_TEXT.language}
              <select
                value={filters.runtime ?? ''}
                onChange={e => update({ runtime: e.target.value || null })}
                className={`${INPUT_CLS} w-32`}
              >
                <option value="">{RUNTIMES_TEXT.all}</option>
                {RUNTIME_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </label>
            <button
              type="button"
              onClick={() => update({ needsActionOnly: !filters.needsActionOnly })}
              aria-pressed={filters.needsActionOnly}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap border transition-colors ${
                filters.needsActionOnly
                  ? 'bg-orange-500/15 text-orange-400 border-orange-500/30'
                  : 'bg-slate-800/60 text-slate-500 border-slate-700 hover:text-slate-300'
              }`}
            >
              <AlertTriangle size={12} />
              {RUNTIMES_TEXT.needsActionOnly}
            </button>
          </div>

          {loading ? (
            <TableLoadingSkeleton columnWidths={['w-40', 'w-24', 'w-24', 'w-32', 'flex-1']} />
          ) : failed ? (
            <EmptyState icon={<Cpu size={24} />} message={RUNTIMES_TEXT.failed} />
          ) : items.length === 0 ? (
            <EmptyState
              icon={<Cpu size={24} />}
              message={filters.needsActionOnly
                ? RUNTIMES_TEXT.emptyNeedsAction
                : RUNTIMES_TEXT.empty}
            />
          ) : (
            <div className="overflow-x-auto -mx-1 px-1">
              <table aria-label={RUNTIMES_TEXT.tableLabel} className="w-full text-sm min-w-[760px]">
                <thead>
                  <tr className="border-b border-slate-800">
                    {!filters.repo && <th className={`${TH} w-48`}>{RUNTIMES_TEXT.columns.app}</th>}
                    <th className={`${TH} w-24`}>{RUNTIMES_TEXT.columns.runtime}</th>
                    <th className={`${TH} w-28`}>{RUNTIMES_TEXT.columns.version}</th>
                    <th className={`${TH} w-36`}>{RUNTIMES_TEXT.columns.state}</th>
                    <th className={`${TH} w-28`}>{RUNTIMES_TEXT.columns.recommended}</th>
                    <th className={`${TH} w-44`}>{RUNTIMES_TEXT.columns.eol}</th>
                    <th className={TH}>{RUNTIMES_TEXT.columns.source}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {items.map(item => (
                    <tr key={`${item.repo_full_name}-${item.runtime}-${item.cycle}-${item.source_path}`}>
                      {!filters.repo && (
                        <td className="py-2.5 pr-3">
                          <p className="text-slate-300 text-xs truncate max-w-[200px]">{item.repo_full_name}</p>
                        </td>
                      )}
                      <td className="py-2.5 pr-3 text-xs text-slate-200">{item.runtime_label}</td>
                      <td className="py-2.5 pr-3 text-xs text-slate-300 tabular-nums">
                        {item.cycle}
                        {!item.pinned && <span className="text-slate-600">{' 以上'}</span>}
                        {item.latest_version && (
                          <p className="text-[10px] text-slate-500">最新 {item.latest_version}</p>
                        )}
                      </td>
                      <td className="py-2.5 pr-3"><StateBadge state={item.state} /></td>
                      <td className="py-2.5 pr-3 text-xs text-slate-300 tabular-nums">
                        {item.recommended_cycle ?? <span className="text-slate-600">—</span>}
                      </td>
                      <td className="py-2.5 pr-3 text-xs text-slate-400"><EolCell item={item} /></td>
                      <td className="py-2.5 text-xs text-slate-500 break-all">{item.source_path}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </PanelFrame>
  )
}
