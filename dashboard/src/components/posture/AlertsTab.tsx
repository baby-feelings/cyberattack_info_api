import type { OperatingStatus } from '../../api/client'
import { AlertsSection } from './AlertsSection'
import { OperatingGroups } from './OperatingGroups'
import { useAlertsSource } from './usePostureData'

// 1つの運用状態ぶんのアラート（取得はここで行う）
function AlertsGroup({ authToken, operating, kinds }: {
  authToken: string
  operating: OperatingStatus
  kinds?: readonly string[]
}) {
  const { source, reload } = useAlertsSource(authToken, operating)
  return <AlertsSection source={source} onRetry={reload} kinds={kinds} />
}

// 小タブ「アラート」の中身。運用中・運用停止中の2区画で、指定した種別（省略で全種別）のアラートを表示する
export function AlertsTab({ authToken, kinds }: { authToken: string; kinds?: readonly string[] }) {
  return (
    <OperatingGroups render={(operating) => (
      <AlertsGroup authToken={authToken} operating={operating} kinds={kinds} />
    )} />
  )
}
