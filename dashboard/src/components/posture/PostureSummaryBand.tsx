import { StatBand, type StatItem } from '../shared/StatBand'
import type { PostureSummary } from './model/PostureSummary'
import { POSTURE_TEXT } from './postureConfig'

// 見出しの数字（未対応のアラート・設定の達成率・外形監視の問題）。
// 取得できなかった元は、数字を出さず、名前を挙げる（0 件と、不明を、混同させない）。
export function PostureSummaryBand({ summary, loading = false }: { summary: PostureSummary; loading?: boolean }) {
  const openAlerts = summary.openAlerts()
  const siteIssues = summary.siteIssues()
  const items: StatItem[] = [
    { value: openAlerts, label: POSTURE_TEXT.summary.openAlerts, tone: openAlerts ? 'red' : 'sky' },
    { value: summary.auditRate(), label: POSTURE_TEXT.summary.auditRate, tone: 'sky' },
    { value: siteIssues, label: POSTURE_TEXT.summary.siteIssues, tone: siteIssues ? 'red' : 'sky' },
  ]
  const unknown = summary.unknownSources()

  return (
    <div className="flex flex-col gap-2">
      <StatBand items={items} loading={loading} />
      {!loading && unknown.length > 0 && (
        <p className="text-xs text-slate-500">
          {POSTURE_TEXT.summary.unknownPrefix} {unknown.map((name) => POSTURE_TEXT.sources[name]).join('・')}
        </p>
      )}
    </div>
  )
}
