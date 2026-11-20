import { Fragment } from 'react'
import { Shield } from 'lucide-react'
import type { VulnerabilityOut } from '../../api/client'
import { DateDividerRow } from '../shared/DateDividerRow'
import { ReloadButton } from '../shared/ReloadButton'
import { isNewDay } from '../shared/dateDay'
import { KevRow } from './KevRow'
import { KEV_TEXT as T, TH } from './kevPanelConfig'

// タイトルと再読み込み
export function KevHeader({ busy, onReload }: { busy: boolean; onReload: () => void }) {
  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-2">
        <Shield size={16} className="text-slate-400" />
        <span className="text-sm font-semibold text-slate-400 uppercase tracking-wider">{T.title}</span>
      </div>
      <ReloadButton onReload={onReload} busy={busy} label={T.reload} />
    </div>
  )
}

// KEV 脆弱性の表（追加日の新しい順。日ごとに区切る）
export function KevTable({ rows }: { rows: VulnerabilityOut[] }) {
  return (
    <div className="overflow-x-auto -mx-1 px-1">
      <table aria-label={T.tableLabel} className="w-full text-sm min-w-[700px]">
        <thead>
          <tr className="border-b border-slate-800">
            <th className={`${TH} w-36`}>{T.columns.cve}</th>
            <th className={`${TH} w-28`}>{T.columns.epss}</th>
            <th className={`${TH} w-40`}>{T.columns.vendor}</th>
            <th className={`${TH} w-40`}>{T.columns.product}</th>
            <th className={TH}>{T.columns.name}</th>
            <th className={`${TH} w-24`}>{T.columns.added}</th>
            <th className="w-5" />
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60">
          {rows.map((item, i) => (
            <Fragment key={item.cve_id}>
              {isNewDay(rows[i - 1]?.date_added, item.date_added) && (
                <DateDividerRow date={item.date_added} colSpan={7} />
              )}
              <KevRow item={item} />
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  )
}
