import { useMemo } from 'react'
import type { OperatingStatus } from '../../api/client'
import { AlertsSection } from './AlertsSection'
import { AuditMatrixSection } from './AuditMatrixSection'
import { PostureSummary } from './model/PostureSummary'
import { PostureSummaryBand } from './PostureSummaryBand'
import { SiteMonitorSection } from './SiteMonitorSection'
import { usePostureData, type Source } from './usePostureData'

// 取得できていればその値、まだ・失敗なら null（見出しの集計は、null を「不明」として扱う）
const valueOf = <T,>(source: Source<T>): T | null => (source.status === 'ready' ? source.value : null)

// 1つの運用状態（運用中 または 運用停止中）ぶんの、集計の帯と3つのセクション。
// 取得は usePostureData、判断は model/ のクラス、文言は postureConfig に任せ、ここは組み立てだけ行う。
export function PostureGroup({ authToken, operating }: { authToken: string; operating: OperatingStatus }) {
  const { audit, alerts, sites, reload } = usePostureData(authToken, operating)

  const summary = useMemo(
    () => new PostureSummary({ alerts: valueOf(alerts), audit: valueOf(audit), sites: valueOf(sites) }),
    [alerts, audit, sites],
  )
  const isLoading = [audit, alerts, sites].some((source) => source.status === 'loading')

  return (
    <div className="flex flex-col gap-4">
      <PostureSummaryBand summary={summary} loading={isLoading} />
      <AuditMatrixSection source={audit} onRetry={() => reload('audit')} />
      <AlertsSection source={alerts} onRetry={() => reload('alerts')} />
      <SiteMonitorSection source={sites} onRetry={() => reload('sites')} />
    </div>
  )
}
