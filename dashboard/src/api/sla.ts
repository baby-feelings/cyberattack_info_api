// 脆弱性への対応状況（SLA・MTTR。Issue #404）関連の API クライアント。
// 検知から解決までの日数を測り、重要度ごとの対応期限を超えたものを取得する（バックエンドの /api/sla）。

import { apiFetch, type OperatingStatus } from './shared'

// 適用中の対応期限（検知から解決までの目標日数）
export interface SlaPolicyOut {
  critical_days: number
  high_days: number
  medium_days: number
  // CISA KEV 掲載済みは、重要度によらずこの日数に短縮される
  kev_days: number
  // 期限の計算から外している OSV ID（受容した検知）
  excluded_osv_ids: string[]
}

export interface SlaSummary {
  open_with_deadline: number
  overdue: number
  resolved: number
  // 平均対応日数（検知から解決まで）。解決が0件なら null
  mttr_days: number | null
}

export interface SlaSeverityStat {
  severity: string
  // 期限なし（LOW・不明）は null
  deadline_days: number | null
  open: number
  overdue: number
  resolved: number
  mttr_days: number | null
}

export interface SlaRepoStat {
  repo_full_name: string
  open: number
  overdue: number
  resolved: number
  mttr_days: number | null
}

export interface SlaOverdueItem {
  repo_full_name: string
  package_name: string
  installed_version: string
  osv_id: string
  severity: string | null
  is_kev: boolean
  is_malicious: boolean
  detected_at: string
  deadline_days: number
  due_at: string
  overdue_days: number
}

export interface SlaReport {
  generated_at: string
  // MTTR を集計する、解決済みの期間（日）
  mttr_window_days: number
  policy: SlaPolicyOut
  summary: SlaSummary
  by_severity: SlaSeverityStat[]
  by_repo: SlaRepoStat[]
  overdue: SlaOverdueItem[]
}

export async function fetchSlaReport(
  authToken?: string, operating?: OperatingStatus,
): Promise<SlaReport> {
  const query = operating && operating !== 'all' ? `?operating=${operating}` : ''
  return apiFetch<SlaReport>(`/api/sla${query}`, authToken)
}
