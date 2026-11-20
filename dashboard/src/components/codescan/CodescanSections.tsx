import { Fragment } from 'react'
import { ScanSearch } from 'lucide-react'
import type { CodescanListResponse } from '../../api/client'
import { DateDividerRow } from '../shared/DateDividerRow'
import { ReloadButton } from '../shared/ReloadButton'
import { isNewDay } from '../shared/dateDay'
import { CodescanRow } from './CodescanRow'
import { CODESCAN_TEXT as T, RESOLVED_OPTIONS, TH } from './codescanPanelConfig'

// タイトルと再読み込み
export function CodescanHeader({ busy, onReload }: { busy: boolean; onReload: () => void }) {
  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ScanSearch size={16} className="text-slate-400" />
          <span className="text-sm font-semibold text-slate-400 uppercase tracking-wider">{T.title}</span>
        </div>
        <ReloadButton onReload={onReload} busy={busy} label={T.reload} />
      </div>
    </div>
  )
}

// 解決状態の絞り込み（未解決・解決済み・全件）
export function ResolvedFilter({
  resolved, onChange,
}: { resolved: boolean | null; onChange: (value: boolean | null) => void }) {
  return (
    <div role="group" aria-label={T.resolvedGroup} className="flex items-center gap-1 bg-slate-800/60 border border-slate-700 rounded-lg px-2.5 py-1.5">
      <span className="text-[10px] text-slate-500 whitespace-nowrap">{T.resolvedLabel}</span>
      {RESOLVED_OPTIONS.map(opt => (
        <button
          key={opt.label}
          onClick={() => onChange(opt.value)}
          aria-pressed={resolved === opt.value}
          className={`px-2 py-0.5 rounded text-[11px] font-medium transition-colors ${
            resolved === opt.value
              ? 'bg-rose-600 text-white'
              : 'text-slate-400 hover:text-slate-300'
          }`}
        >
          {opt.label}
        </button>
      ))}
    </div>
  )
}

// コード脆弱性の表。アプリを1つ選んでいるときは、リポジトリの列を出さない
export function CodescanTable({
  result, selectedRepo, authToken, onExceptionChanged,
}: {
  result: CodescanListResponse
  selectedRepo: string | null
  authToken?: string
  onExceptionChanged: () => void
}) {
  return (
    <div className="overflow-x-auto -mx-1 px-1">
      <table aria-label={T.tableLabel} className="w-full text-sm min-w-[560px]">
        <thead>
          <tr className="border-b border-slate-800">
            <th className={`${TH} w-20`}>{T.columns.severity}</th>
            <th className={`${TH} w-16`}>{T.columns.cvss}</th>
            {!selectedRepo && <th className={`${TH} w-40`}>{T.columns.repo}</th>}
            <th className={TH}>{T.columns.file}</th>
            <th className={TH}>{T.columns.rule}</th>
            <th className={`${TH} w-24`}>{T.columns.detected}</th>
            <th className="w-5" />
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60">
          {result.data.map((item, i) => (
            <Fragment key={`${item.repo_full_name}-${item.file_path}-${item.rule_id}-${item.line_start}-${i}`}>
              {/* 一覧は検知日の新しい順（API 側の並び）。検知日ごとに区切る */}
              {isNewDay(result.data[i - 1]?.detected_at, item.detected_at) && (
                <DateDividerRow date={item.detected_at} colSpan={selectedRepo ? 6 : 7} />
              )}
              <CodescanRow
                item={item}
                showRepo={!selectedRepo}
                authToken={authToken}
                onExceptionChanged={onExceptionChanged}
              />
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  )
}
