import type { ReactNode } from 'react'
import type { OperatingStatus } from '../../api/client'
import { AuditMatrixSection } from './AuditMatrixSection'
import { OperatingGroups } from './OperatingGroups'
import { SiteMonitorSection } from './SiteMonitorSection'
import { useAuditSource, useSitesSource } from './usePostureData'

// 1つの運用状態ぶんの、設定の監査（取得はここで行う）
function AuditGroup({ authToken, operating }: { authToken: string; operating: OperatingStatus }) {
  const { source, reload } = useAuditSource(authToken, operating)
  return <AuditMatrixSection source={source} onRetry={reload} />
}

// 1つの運用状態ぶんの、外形監視
function SitesGroup({ authToken, operating }: { authToken: string; operating: OperatingStatus }) {
  const { source, reload } = useSitesSource(authToken, operating)
  return <SiteMonitorSection source={source} onRetry={reload} />
}

// 運用中・運用停止中の2区画で、同じ取得元の画面を出す共通の枠
function inOperatingGroups(render: (operating: OperatingStatus) => ReactNode) {
  return <OperatingGroups render={render} />
}

// 小タブ「設定の監査」の中身（リポジトリ × 点検項目）
export function AuditTab({ authToken }: { authToken: string }) {
  return inOperatingGroups((operating) => <AuditGroup authToken={authToken} operating={operating} />)
}

// 外形監視の中身（公開サイトの TLS・ヘッダー・露出ファイルなど）
export function SitesTab({ authToken }: { authToken: string }) {
  return inOperatingGroups((operating) => <SitesGroup authToken={authToken} operating={operating} />)
}
