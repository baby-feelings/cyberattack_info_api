// CISA KEV（Known Exploited Vulnerabilities）関連の API クライアント。

import { apiFetch, BASE_URL, type MonthlyStat } from './shared'

export interface HealthResponse {
  status: 'ok' | 'degraded'
  environment: string
  db_connected: boolean
}

export interface VulnerabilityOut {
  cve_id: string
  vendor_project: string
  product: string
  vulnerability_name: string
  description: string
  required_action: string | null
  date_added: string
  // EPSS（Exploit Prediction Scoring System）: FIRSTが日次算出する
  // 「今後30日以内に悪用される確率」（0.0〜1.0）。未取得時はnull
  epss_score: number | null
  epss_percentile: number | null
  epss_updated_at: string | null
}

export interface VendorStat {
  vendor_project: string
  count: number
}

export interface StatsResponse {
  total_vulnerabilities: number
  top_vendors: VendorStat[]
  monthly_trend: MonthlyStat[]
}

export interface VulnerabilityListResponse {
  total: number
  page: number
  per_page: number
  data: VulnerabilityOut[]
}

// ヘルスチェック（認証不要）
export async function fetchHealth(): Promise<HealthResponse> {
  const res = await fetch(`${BASE_URL}/health`)
  if (!res.ok) throw new Error(`Health check failed: ${res.status}`)
  return res.json()
}

// 直近 N 日の脆弱性一覧
export async function fetchRecent(days = 30): Promise<VulnerabilityOut[]> {
  return apiFetch<VulnerabilityOut[]>(`/api/vulnerabilities/recent?days=${days}`)
}

// 統計情報（ベンダー別ランキング・月別トレンド）
export async function fetchStats(): Promise<StatsResponse> {
  return apiFetch<StatsResponse>('/api/vulnerabilities/stats')
}

// 脆弱性一覧（ページネーション・キーワード検索対応）
export async function fetchVulnerabilities(params: {
  page?: number
  perPage?: number
  search?: string
}): Promise<VulnerabilityListResponse> {
  const p = new URLSearchParams()
  p.set('page', String(params.page ?? 1))
  p.set('per_page', String(params.perPage ?? 50))
  if (params.search) p.set('search', params.search)
  return apiFetch<VulnerabilityListResponse>(`/api/vulnerabilities?${p}`)
}
