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

// POST リクエスト共通ヘルパー（text/plain ボディ）
async function apiPost<T>(path: string, body: string): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method: 'POST',
    headers: { 'X-API-KEY': API_KEY, 'Content-Type': 'text/plain' },
    body,
  })
  if (!res.ok) throw new Error(`API error ${res.status}: ${path}`)
  return res.json() as Promise<T>
}

// requirements.txt スキャン
export async function scanRequirements(text: string): Promise<ScanResponse> {
  return apiPost<ScanResponse>('/api/scan/requirements', text)
}

// package.json スキャン
export async function scanPackageJson(text: string): Promise<ScanResponse> {
  return apiPost<ScanResponse>('/api/scan/package-json', text)
}

// スキャン履歴取得
export async function fetchScanHistory(limit = 10): Promise<ScanResultOut[]> {
  return apiFetch<ScanResultOut[]>(`/api/scan/history?limit=${limit}`)
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

export interface VulnerabilityFinding {
  package_name: string
  package_version: string | null
  source: 'OSV' | 'CISA_KEV'
  vuln_id: string
  severity: string | null
  summary: string
  details: string | null
  fixed_versions: string[]
  references: string[]
}

export interface ScanResponse {
  scanned_packages: number
  total_findings: number
  findings: VulnerabilityFinding[]
}

export interface ScanResultOut {
  id: number
  scan_type: string
  scanned_packages: number
  total_findings: number
  findings: VulnerabilityFinding[]
  scanned_at: string
}

// ── OSV 脆弱性 ─────────────────────────────────────────────

export interface OsvVulnerabilityOut {
  osv_id: string
  ecosystem: string
  package_name: string
  aliases: string[]
  summary: string
  details: string | null
  severity: string | null
  cvss_score: number | null
  affected_versions: string[]
  fixed_versions: string[]
  references: string[]
  published: string
  modified: string
}

export interface OsvEcosystemStat {
  ecosystem: string
  count: number
}

export interface OsvSeverityStat {
  severity: string
  count: number
}

export interface OsvStatsResponse {
  total: number
  ecosystems: OsvEcosystemStat[]
  severities: OsvSeverityStat[]
  monthly_trend: MonthlyStat[]
}

export interface OsvListResponse {
  total: number
  page: number
  per_page: number
  data: OsvVulnerabilityOut[]
}

export async function fetchOsvList(params: {
  page?: number
  perPage?: number
  days?: number
  ecosystem?: string | null
  severity?: string | null
  search?: string
  sortBy?: 'modified' | 'cvss'
}): Promise<OsvListResponse> {
  const p = new URLSearchParams()
  p.set('page', String(params.page ?? 1))
  p.set('per_page', String(params.perPage ?? 50))
  p.set('days', String(params.days ?? 90))
  if (params.ecosystem) p.set('ecosystem', params.ecosystem)
  if (params.severity) p.set('severity', params.severity)
  if (params.search) p.set('search', params.search)
  if (params.sortBy) p.set('sort_by', params.sortBy)
  return apiFetch<OsvListResponse>(`/api/osv?${p}`)
}

export async function fetchOsvStats(days = 90): Promise<OsvStatsResponse> {
  return apiFetch<OsvStatsResponse>(`/api/osv/stats?days=${days}`)
}
