import { useEffect, useState } from 'react'
import {
  fetchCodescanStats, fetchDepscanStats, fetchGithubAlerts, fetchRepoAudit, fetchRuntimes,
  fetchSiteMonitor, fetchSlaReport,
} from '../../api/client'
import { ALERT_KIND_GROUPS } from '../posture/postureConfig'
import { OverviewMetric } from './OverviewMetric'
import { OVERVIEW_EOL_STATES, OVERVIEW_METRICS, OVERVIEW_OPERATING } from './overviewConfig'

type Loader = (authToken: string) => Promise<number | null>

const operating = OVERVIEW_OPERATING
const countAlerts = async (authToken: string, kinds: readonly string[]) =>
  (await fetchGithubAlerts({ operating, authToken })).data.filter((a) => kinds.includes(a.kind)).length

// 指標ごとの取得。指標の id（overviewConfig）と対応させる。1つが失敗しても、ほかには影響しない
const LOADERS: Record<string, Loader> = {
  'dep-open': async (t) => (await fetchDepscanStats(t, operating)).total,
  'dep-overdue': async (t) => (await fetchSlaReport(t, operating)).summary.overdue,
  'dep-eol': async (t) =>
    (await fetchRuntimes({ operating, authToken: t })).data.filter((r) => OVERVIEW_EOL_STATES.includes(r.state)).length,
  'dep-alerts': (t) => countAlerts(t, ALERT_KIND_GROUPS.dependencies),
  'code-open': async (t) => (await fetchCodescanStats(t, operating)).total,
  'code-alerts': (t) => countAlerts(t, ALERT_KIND_GROUPS.code),
  // 点検できたリポジトリの平均。1件も点検できていなければ、不明
  'code-audit': async (t) => {
    const scores = (await fetchRepoAudit({ operating, authToken: t })).data
      .map((r) => r.score).filter((s): s is number => s !== null)
    return scores.length === 0 ? null : Math.round(scores.reduce((a, b) => a + b, 0) / scores.length)
  },
  'ops-sites': async (t) => (await fetchSiteMonitor({ operating, authToken: t })).sites_with_issues,
}

// 概要の指標を、取得して返す。各取得は独立で、失敗した指標は value: null（不明）
export function useOverviewData(authToken: string): { metrics: OverviewMetric[]; loading: boolean; reload: () => void } {
  const [values, setValues] = useState<Record<string, number | null>>({})
  // 取得が完了した条件（トークン＋再読み込みの回数）。今の条件と違えば「取得中」
  const [doneKey, setDoneKey] = useState<string | null>(null)
  // 再読み込みのボタンを押すたびに増やし、すべての指標を取り直す
  const [attempt, setAttempt] = useState(0)
  const key = `${authToken}|${attempt}`

  useEffect(() => {
    let cancelled = false
    const settled = OVERVIEW_METRICS.map(async (def) => {
      const value = await (LOADERS[def.id]?.(authToken) ?? Promise.resolve(null)).catch(() => null)
      if (!cancelled) setValues((prev) => ({ ...prev, [def.id]: value }))
    })
    void Promise.all(settled).then(() => { if (!cancelled) setDoneKey(key) })
    return () => { cancelled = true }
  }, [authToken, key])

  const metrics = OVERVIEW_METRICS.map((def) => new OverviewMetric({
    ...def, value: def.id in values ? values[def.id] : null,
  }))
  return { metrics, loading: doneKey !== key, reload: () => setAttempt((n) => n + 1) }
}
