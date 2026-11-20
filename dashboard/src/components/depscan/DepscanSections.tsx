import { Fragment, type ReactNode } from 'react'
import { Bug, CheckCircle2, Sparkles } from 'lucide-react'
import { DateDividerRow } from '../shared/DateDividerRow'
import { ReloadButton } from '../shared/ReloadButton'
import { isNewDay } from '../shared/dateDay'
import { DepscanGroupRow } from './DepscanGroupRow'
import { groupLatestDetectedAt, type FindingGroup } from './grouping'
import { DEPSCAN_TEXT as T, TH } from './depscanPanelConfig'

// 左のアプリ一覧に出す件数バッジ。対応が必要な件数（CRITICAL・HIGH）を目立たせ、
// 無いアプリは薄い数字（総件数）にする
export function RepoBadge({ crit, high, total }: { crit: number; high: number; total: number }) {
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

// 新着データ通知バナー（自動更新はせず、ボタン押下で明示的に更新）
export function NewDataBanner({ onRefresh }: { onRefresh: () => void }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-lg border border-violet-500/30 bg-violet-500/10 px-3 py-2 text-xs text-violet-300">
      <span className="flex items-center gap-1.5">
        <Sparkles size={13} />
        {T.newData}
      </span>
      <button
        onClick={onRefresh}
        className="px-2.5 py-1 rounded-md bg-violet-600 hover:bg-violet-500 text-white font-medium transition-colors"
      >
        {T.refresh}
      </button>
    </div>
  )
}

// タイトルと再読み込み（依存パッケージ・言語・対応状況・Dependabot運用状況は、「依存ライブラリ」タブの小タブに移した）
export function DepscanHeader({ loading, onReload }: { loading: boolean; onReload: () => void }) {
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2 min-w-0">
          <Bug size={16} className="text-slate-400 shrink-0" />
          <span className="text-sm font-semibold text-slate-400 uppercase tracking-wider">{T.title}</span>
        </div>
        <ReloadButton onReload={onReload} busy={loading} label={T.reload} />
      </div>
    </div>
  )
}

// オーナーの絞り込み（2つ以上あるときだけ出す）
export function OwnerFilter({
  owners, owner, onSelect,
}: { owners: string[]; owner: string | null; onSelect: (owner: string) => void }) {
  if (owners.length <= 1) return null
  return (
    <div role="group" aria-label={T.ownerGroup} className="flex flex-wrap gap-1.5">
      {['ALL', ...owners].map(o => {
        const active = (o === 'ALL' && owner === null) || o === owner
        return (
          <button
            key={o}
            onClick={() => onSelect(o)}
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
  )
}

// 解決済みを含めるかの切り替え
export function ResolvedToggle({ active, onToggle }: { active: boolean; onToggle: () => void }) {
  return (
    <button
      onClick={onToggle}
      aria-pressed={active}
      className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
        active
          ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
          : 'bg-slate-800/60 text-slate-500 border-slate-700 hover:text-slate-300'
      }`}
    >
      <CheckCircle2 size={12} />
      {T.showResolved}
    </button>
  )
}

// 脆弱性の表（パッケージ単位に集約）。アプリを1つ選んでいるときは、リポジトリの列を出さない
export function DepscanTable({
  pageGroups, sortBy, activeRepo, authToken, onExceptionChanged,
}: {
  pageGroups: FindingGroup[]
  sortBy: string
  activeRepo: string | null
  authToken?: string
  onExceptionChanged: () => void
}): ReactNode {
  return (
    <div className="overflow-x-auto -mx-1 px-1">
      <table aria-label={T.tableLabel} className="w-full text-sm min-w-[560px]">
        <thead>
          <tr className="border-b border-slate-800">
            <th className={`${TH} w-24`}>{T.columns.severity}</th>
            {!activeRepo && <th className={`${TH} w-52`}>{T.columns.repo}</th>}
            <th className={`${TH} w-40`}>{T.columns.package}</th>
            <th className={`${TH} w-32`}>{T.columns.fixed}</th>
            <th className={`${TH} w-28`}>{T.columns.reachability}</th>
            <th className={`${TH} w-24`}>{T.columns.detected}</th>
            <th className="w-5" />
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60">
          {pageGroups.map((group, i) => (
            <Fragment key={`${group.repo_full_name}-${group.package_name}-${group.installed_version}-${i}`}>
              {/* 検知日順のときだけ、検知日ごとに区切る（重要度順では日付が混ざるため出さない） */}
              {sortBy === 'date' && isNewDay(
                pageGroups[i - 1] && groupLatestDetectedAt(pageGroups[i - 1]),
                groupLatestDetectedAt(group),
              ) && (
                <DateDividerRow date={groupLatestDetectedAt(group)} colSpan={activeRepo ? 6 : 7} />
              )}
              <DepscanGroupRow
                group={group}
                showRepo={!activeRepo}
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
