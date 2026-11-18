import { Fragment } from 'react'
import { Shield, RefreshCw } from 'lucide-react'
import type { OsvListResponse, OsvStatsResponse } from '../../api/client'
import { DateDividerRow } from '../shared/DateDividerRow'
import { isNewDay } from '../shared/dateDay'
import { OsvRow } from './OsvRow'
import { ECOSYSTEMS, OSV_TEXT as T, SEVERITY_CLS, TH } from './osvPanelConfig'

// タイトルと再読み込み
export function OsvHeader({
  period, busy, onReload,
}: { period: number; busy: boolean; onReload: () => void }) {
  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-2">
        <Shield size={16} className="text-slate-400" />
        <span className="text-sm font-semibold text-slate-400 uppercase tracking-wider">{T.title(period)}</span>
      </div>
      <button
        onClick={onReload}
        disabled={busy}
        className="text-slate-500 hover:text-slate-300 transition-colors disabled:opacity-40 p-1 rounded"
        title={T.reload}
      >
        <RefreshCw size={13} className={busy ? 'animate-spin' : ''} />
      </button>
    </div>
  )
}

// エコシステムの絞り込み（エコシステム別の件数つき）
export function EcosystemFilter({
  ecosystem, stats, onSelect,
}: { ecosystem: string | null; stats: OsvStatsResponse | null; onSelect: (eco: string) => void }) {
  return (
    <div role="group" aria-label={T.ecosystemGroup} className="flex flex-wrap gap-1.5">
      {ECOSYSTEMS.map(eco => {
        const active = (eco === 'ALL' && ecosystem === null) || eco === ecosystem
        return (
          <button
            key={eco}
            onClick={() => onSelect(eco)}
            aria-pressed={active}
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
  )
}

// OSV 脆弱性の表
export function OsvTable({ result, sortBy }: { result: OsvListResponse; sortBy: string }) {
  return (
    <div className="overflow-x-auto -mx-1 px-1">
      <table aria-label={T.tableLabel} className="w-full text-sm min-w-[700px]">
        <thead>
          <tr className="border-b border-slate-800">
            <th className={`${TH} w-20`}>{T.columns.severity}</th>
            <th className={`${TH} w-44`}>{T.columns.osvId}</th>
            <th className={`${TH} w-24`}>{T.columns.ecosystem}</th>
            <th className={`${TH} w-36`}>{T.columns.package}</th>
            <th className={TH}>{T.columns.summary}</th>
            <th className={`${TH} w-24`}>{T.columns.modified}</th>
            <th className="w-5" />
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60">
          {result.data.map((item, i) => (
            <Fragment key={`${item.osv_id}-${item.ecosystem}-${item.package_name}-${i}`}>
              {/* 更新日順のときだけ、更新日ごとに区切る（CVSS 順では日付が混ざるため出さない） */}
              {sortBy === 'modified' && isNewDay(result.data[i - 1]?.modified, item.modified) && (
                <DateDividerRow date={item.modified} colSpan={7} />
              )}
              <OsvRow item={item} severityClassMap={SEVERITY_CLS} />
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  )
}
