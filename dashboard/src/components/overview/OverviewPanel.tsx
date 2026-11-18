import { useOverviewData } from './useOverviewData'
import {
  METRIC_STATE_CLASS, OVERVIEW_GROUP_LABEL, OVERVIEW_METRICS, OVERVIEW_TEXT, type NavTarget, type OverviewGroup,
} from './overviewConfig'

// 概要: グループごとに、対応が必要な件数のカードを並べる。カードを押すと、該当のタブ・小タブへ移る
export function OverviewPanel({ authToken, onNavigate }: {
  authToken: string
  onNavigate: (target: NavTarget) => void
}) {
  const { metrics, loading } = useOverviewData(authToken)
  const groups = [...new Set(OVERVIEW_METRICS.map((m) => m.group))] as OverviewGroup[]

  if (loading) {
    return <div role="status" aria-label={OVERVIEW_TEXT.loading} className="h-40 rounded-2xl bg-slate-800/60 animate-pulse" />
  }
  return (
    <div className="grid gap-6 md:grid-cols-3">
      {groups.map((group) => (
        <section key={group} aria-label={OVERVIEW_GROUP_LABEL[group]} className="flex flex-col gap-3">
          <h3 className="text-sm font-semibold text-slate-300">{OVERVIEW_GROUP_LABEL[group]}</h3>
          {metrics.filter((m) => OVERVIEW_METRICS.find((d) => d.id === m.id)?.group === group).map((m) => {
            const cls = METRIC_STATE_CLASS[m.state]
            return (
              <button
                key={m.id}
                type="button"
                onClick={() => onNavigate(m.target)}
                className={`text-left rounded-xl border ${cls.border} bg-slate-900 p-4 hover:bg-slate-800/70 transition-colors`}
              >
                <span className="block text-xs text-slate-400">{m.label}</span>
                <span className={`block text-2xl font-bold tabular-nums mt-1 ${cls.value}`}>{m.display()}</span>
              </button>
            )
          })}
        </section>
      ))}
    </div>
  )
}
