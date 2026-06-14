// API クライアント: 本番 API への全リクエストを集約する

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'https://cyberattack-info-api.onrender.com'
const API_KEY = import.meta.env.VITE_API_KEY || ''

async function apiFetch<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { 'X-API-KEY': API_KEY },
  })
  if (!res.ok) throw new Error(`API error ${res.status}: ${path}`)
  return res.json() as Promise<T>
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

// 型定義
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
}

export interface VendorStat {
  vendor_project: string
  count: number
}

export interface MonthlyStat {
  year_month: string
  count: number
}

export interface StatsResponse {
  total_vulnerabilities: number
  top_vendors: VendorStat[]
  monthly_trend: MonthlyStat[]
}
