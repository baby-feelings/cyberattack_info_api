import { useState } from 'react'
import { ExternalLink } from 'lucide-react'
import { SCREEN_FETCH_SOURCE } from '../freshness/freshnessConfig'
import { SeverityBadge } from '../shared/Badge'
import { AlertKindIcon } from './AlertKindIcon'
import { AlertKind } from './model/AlertKind'
import type { AlertList } from './model/AlertList'
import { ALERT_SEVERITY_CLASS, ALERT_SEVERITY_RANK, POSTURE_TEXT } from './postureConfig'
import { PostureSection } from './PostureSection'
import type { Source } from './usePostureData'

// GitHub のセキュリティアラート（シークレット・Dependabot・コードスキャン）の一覧。
export function AlertsSection({ source, onRetry }: { source: Source<AlertList>; onRetry: () => void }) {
  return (
    <PostureSection
      title={POSTURE_TEXT.alerts.title}
      crawlerType={SCREEN_FETCH_SOURCE.postureAlerts}
      source={source}
      onRetry={onRetry}
    >
      {(list) => <AlertsView list={list} />}
    </PostureSection>
  )
}

const selectCls = 'rounded-lg bg-slate-800 border border-slate-700 px-2 py-1.5 text-sm text-slate-200'

function AlertsView({ list }: { list: AlertList }) {
  const [kind, setKind] = useState('')
  const [severity, setSeverity] = useState('')
  const rows = list.filter({ kind, severity }).sorted()
  const kinds = Object.keys(list.countsByKind())

  return (
    <div className="flex flex-col gap-3">
      {list.count() === 0 ? (
        <p className="text-sm text-slate-400">{POSTURE_TEXT.alerts.empty}</p>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-3">
            <select aria-label={POSTURE_TEXT.alerts.kind} value={kind} onChange={(e) => setKind(e.target.value)} className={selectCls}>
              <option value="">{POSTURE_TEXT.alerts.kind}: {POSTURE_TEXT.all}</option>
              {kinds.map((k) => <option key={k} value={k}>{AlertKind.of(k).label()}</option>)}
            </select>
            <select aria-label={POSTURE_TEXT.alerts.severity} value={severity} onChange={(e) => setSeverity(e.target.value)} className={selectCls}>
              <option value="">{POSTURE_TEXT.alerts.severity}: {POSTURE_TEXT.all}</option>
              {Object.keys(ALERT_SEVERITY_RANK).map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>

          <div className="overflow-x-auto">
            <table aria-label={POSTURE_TEXT.alerts.title} className="min-w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-slate-400">
                  <th scope="col" className="px-3 py-2 font-medium">{POSTURE_TEXT.alerts.columns.severity}</th>
                  <th scope="col" className="px-3 py-2 font-medium">{POSTURE_TEXT.alerts.columns.kind}</th>
                  <th scope="col" className="px-3 py-2 font-medium">{POSTURE_TEXT.alerts.columns.repo}</th>
                  <th scope="col" className="px-3 py-2 font-medium">{POSTURE_TEXT.alerts.columns.title}</th>
                  <th scope="col" className="px-3 py-2 font-medium">{POSTURE_TEXT.alerts.columns.tool}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((alert) => {
                  const url = alert.safeUrl()
                  return (
                    <tr key={`${alert.kind.kind}-${alert.repo}-${alert.number}`} className="border-t border-slate-800 align-top">
                      <td className="px-3 py-2"><SeverityBadge severity={alert.severity} classMap={ALERT_SEVERITY_CLASS} /></td>
                      <td className="px-3 py-2">
                        <span className="inline-flex items-center gap-1.5 text-slate-300">
                          <AlertKindIcon name={alert.kind.icon()} />
                          <span>{alert.kind.label()}</span>
                        </span>
                      </td>
                      <td className="px-3 py-2 text-slate-300 whitespace-nowrap">{alert.repo}</td>
                      <td className="px-3 py-2 text-slate-200">
                        {url ? (
                          // 外部のページを新しいタブで開く。opener を渡さない
                          <a href={url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-sky-400 hover:underline">
                            {alert.title}
                            <ExternalLink size={12} aria-hidden="true" />
                            <span className="sr-only">{POSTURE_TEXT.alerts.opensInNewTab}</span>
                          </a>
                        ) : (
                          <span>{alert.title}</span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-slate-400">{alert.tool() ?? '—'}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </>
      )}

      {list.unavailable.length > 0 && (
        <div role="region" aria-label={POSTURE_TEXT.alerts.unavailableTitle} className="rounded-lg border border-slate-700 bg-slate-800/40 p-3 text-xs text-slate-400">
          <p className="font-medium text-slate-300 mb-1">{POSTURE_TEXT.alerts.unavailableTitle}</p>
          <ul className="flex flex-col gap-0.5">
            {list.unavailable.map((u) => (
              <li key={`${u.kind}-${u.repo_full_name}`}>
                {u.repo_full_name} — {AlertKind.of(u.kind).label()}: {u.reason ?? POSTURE_TEXT.alerts.unknownReason}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
