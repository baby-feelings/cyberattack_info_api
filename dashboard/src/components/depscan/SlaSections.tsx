import { Timer } from 'lucide-react'
import type { SlaReport } from '../../api/client'
import { EmptyState } from '../shared/VulnPanelParts'
import { SLA_TEXT, SLA_TH as TH } from './slaConfig'

// 平均対応日数の表示（解決が0件のときは「—」）
function mttrText(mttr: number | null): string {
  return mttr === null ? SLA_TEXT.noMttr : `${mttr} ${SLA_TEXT.unit.days}`
}

// 期限超過が1件でもあれば目立たせる。0件は落ち着いた色にする
function Tile({ label, value, tone = 'neutral', hint }: {
  label: string; value: string; tone?: 'neutral' | 'danger'; hint?: string
}) {
  const cls = tone === 'danger'
    ? 'border-red-500/30 bg-red-500/10 text-red-300'
    : 'border-slate-800 bg-slate-900 text-slate-200'
  return (
    <div className={`rounded-xl border px-4 py-3 ${cls}`} title={hint}>
      <p className="text-[11px] text-slate-500">{label}</p>
      <p className="text-xl font-bold tabular-nums mt-0.5">{value}</p>
    </div>
  )
}

function OverdueBadge({ count }: { count: number }) {
  if (count === 0) return <span className="text-slate-600 tabular-nums">0</span>
  return <span className="text-red-400 font-semibold tabular-nums">{count}</span>
}

export function SlaSummaryTiles({ report }: { report: SlaReport }) {
  const { summary } = report
  const count = (n: number) => `${n} ${SLA_TEXT.unit.count}`
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3" aria-label={SLA_TEXT.summaryLabel}>
      <Tile label={SLA_TEXT.tile.overdue} value={count(summary.overdue)} tone={summary.overdue > 0 ? 'danger' : 'neutral'} />
      <Tile label={SLA_TEXT.tile.open} value={count(summary.open_with_deadline)} />
      <Tile label={SLA_TEXT.tile.resolved(report.mttr_window_days)} value={count(summary.resolved)} />
      <Tile label={SLA_TEXT.tile.mttr} value={mttrText(summary.mttr_days)} hint={SLA_TEXT.tile.mttrHint} />
    </div>
  )
}

export function SlaPolicyNote({ report }: { report: SlaReport }) {
  const { policy } = report
  const days = SLA_TEXT.unit.days
  return (
    <p className="text-xs text-slate-500" aria-label={SLA_TEXT.policy.label}>
      {SLA_TEXT.policy.prefix} CRITICAL {policy.critical_days}{days} / HIGH {policy.high_days}{days} /
      MEDIUM {policy.medium_days}{days} / {SLA_TEXT.policy.kev} {policy.kev_days}{days}
      {policy.excluded_osv_ids.length > 0 && (
        <span>{SLA_TEXT.policy.excluded(policy.excluded_osv_ids.length)}</span>
      )}
    </p>
  )
}

export function SlaOverdueTable({ report }: { report: SlaReport }) {
  const t = SLA_TEXT.overdue
  if (report.overdue.length === 0) {
    return <EmptyState icon={<Timer size={24} />} message={t.empty} />
  }
  return (
    <div className="overflow-x-auto -mx-1 px-1">
      <table aria-label={t.tableLabel} className="w-full text-sm min-w-[760px]">
        <thead>
          <tr className="border-b border-slate-800">
            <th className={`${TH} w-20`}>{t.columns.severity}</th>
            <th className={`${TH} w-48`}>{t.columns.repo}</th>
            <th className={TH}>{t.columns.package}</th>
            <th className={`${TH} w-24`}>{t.columns.deadline}</th>
            <th className={`${TH} w-28`}>{t.columns.over}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60">
          {report.overdue.map(item => (
            <tr key={`${item.repo_full_name}-${item.package_name}-${item.installed_version}-${item.osv_id}`}>
              <td className="py-2.5 pr-3 text-xs text-slate-300">
                {item.severity ?? t.unknownSeverity}
                {item.is_malicious && <span className="ml-1" title={t.maliciousTitle}>🛑</span>}
                {item.is_kev && (
                  <span className="ml-1 px-1 rounded text-[9px] font-bold bg-red-500/20 text-red-400 border border-red-500/40">
                    {t.kev}
                  </span>
                )}
              </td>
              <td className="py-2.5 pr-3 text-xs text-slate-300 truncate max-w-[200px]">{item.repo_full_name}</td>
              <td className="py-2.5 pr-3 text-xs text-slate-200">
                {item.package_name}
                <span className="text-slate-500 tabular-nums"> {item.installed_version}</span>
                <p className="text-[10px] text-slate-600">{item.osv_id}</p>
              </td>
              <td className="py-2.5 pr-3 text-xs text-slate-400 tabular-nums">{item.deadline_days} {SLA_TEXT.unit.days}</td>
              <td className="py-2.5 text-xs text-red-400 font-semibold tabular-nums">{t.daysOver(item.overdue_days)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function SlaBySeverityTable({ report }: { report: SlaReport }) {
  const t = SLA_TEXT.bySeverity
  return (
    <div className="overflow-x-auto">
      <h3 className="text-xs font-semibold text-slate-500 mb-2">{t.title}</h3>
      <table aria-label={t.tableLabel} className="w-full text-sm">
        <thead>
          <tr className="border-b border-slate-800">
            <th className={TH}>{t.columns.severity}</th>
            <th className={TH}>{t.columns.deadline}</th>
            <th className={TH}>{t.columns.open}</th>
            <th className={TH}>{t.columns.over}</th>
            <th className={TH}>{t.columns.mttr}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60">
          {report.by_severity.map(s => (
            <tr key={s.severity}>
              <td className="py-2 pr-3 text-xs text-slate-300">{s.severity}</td>
              <td className="py-2 pr-3 text-xs text-slate-400 tabular-nums">
                {s.deadline_days === null ? SLA_TEXT.noMttr : `${s.deadline_days} ${SLA_TEXT.unit.days}`}
              </td>
              <td className="py-2 pr-3 text-xs text-slate-300 tabular-nums">{s.open}</td>
              <td className="py-2 pr-3 text-xs"><OverdueBadge count={s.overdue} /></td>
              <td className="py-2 text-xs text-slate-400 tabular-nums">{mttrText(s.mttr_days)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function SlaByRepoTable({ report }: { report: SlaReport }) {
  const t = SLA_TEXT.byRepo
  return (
    <div className="overflow-x-auto">
      <h3 className="text-xs font-semibold text-slate-500 mb-2">{t.title}</h3>
      <table aria-label={t.tableLabel} className="w-full text-sm">
        <thead>
          <tr className="border-b border-slate-800">
            <th className={TH}>{t.columns.repo}</th>
            <th className={TH}>{t.columns.open}</th>
            <th className={TH}>{t.columns.over}</th>
            <th className={TH}>{t.columns.mttr}</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60">
          {report.by_repo.map(r => (
            <tr key={r.repo_full_name}>
              <td className="py-2 pr-3 text-xs text-slate-300 truncate max-w-[220px]">{r.repo_full_name}</td>
              <td className="py-2 pr-3 text-xs text-slate-300 tabular-nums">{r.open}</td>
              <td className="py-2 pr-3 text-xs"><OverdueBadge count={r.overdue} /></td>
              <td className="py-2 text-xs text-slate-400 tabular-nums">{mttrText(r.mttr_days)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
