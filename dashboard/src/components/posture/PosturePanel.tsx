import { useMemo, useState } from 'react'
import type { OperatingStatus } from '../../api/client'
import { OperatingFilter } from '../shared/OperatingFilter'
import { AlertsSection } from './AlertsSection'
import { AuditMatrixSection } from './AuditMatrixSection'
import { PostureSummary } from './model/PostureSummary'
import { PostureSummaryBand } from './PostureSummaryBand'
import { SiteMonitorSection } from './SiteMonitorSection'
import { usePostureData, type Source } from './usePostureData'

// 取得できていればその値、まだ・失敗なら null（見出しの集計は、null を「不明」として扱う）
const valueOf = <T,>(source: Source<T>): T | null => (source.status === 'ready' ? source.value : null)

// 「態勢」タブ。組み立てのみ（取得は usePostureData、判断は model/ のクラス、文言は postureConfig）。
export function PosturePanel({ authToken }: { authToken: string }) {
  // 初期表示は運用中のみ（運用停止中のアプリに埋もれず、運用中のものを見やすくするため）
  const [operating, setOperating] = useState<OperatingStatus>('active')
  const { audit, alerts, sites, reload } = usePostureData(authToken, operating)

  const summary = useMemo(
    () => new PostureSummary({ alerts: valueOf(alerts), audit: valueOf(audit), sites: valueOf(sites) }),
    [alerts, audit, sites],
  )
  const isLoading = [audit, alerts, sites].some((source) => source.status === 'loading')

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <PostureSummaryBand summary={summary} loading={isLoading} />
        <OperatingFilter value={operating} onChange={setOperating} />
      </div>
      <AuditMatrixSection source={audit} onRetry={() => reload('audit')} />
      <AlertsSection source={alerts} onRetry={() => reload('alerts')} />
      <SiteMonitorSection source={sites} onRetry={() => reload('sites')} />
    </div>
  )
}
