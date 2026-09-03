// API クライアント: 本番 API への全リクエストを集約する

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'https://cyberattack-info-api.onrender.com'
const API_KEY = import.meta.env.VITE_API_KEY || ''

// authToken 指定時は X-API-KEY の代わりに GitHub ログインのセッショントークンを送る
// （DEPSCAN のログインユーザー向けエンドポイント用。サーバー側で本人所有リポジトリに強制的に絞り込まれる）
async function apiFetch<T>(path: string, authToken?: string): Promise<T> {
  const headers: Record<string, string> = authToken
    ? { Authorization: `Bearer ${authToken}` }
    : { 'X-API-KEY': API_KEY }
  const res = await fetch(`${BASE_URL}${path}`, { headers })
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
  p.set('days', String(params.days ?? 180))
  if (params.ecosystem) p.set('ecosystem', params.ecosystem)
  if (params.severity) p.set('severity', params.severity)
  if (params.search) p.set('search', params.search)
  if (params.sortBy) p.set('sort_by', params.sortBy)
  return apiFetch<OsvListResponse>(`/api/osv?${p}`)
}

export async function fetchOsvStats(days = 180): Promise<OsvStatsResponse> {
  return apiFetch<OsvStatsResponse>(`/api/osv/stats?days=${days}`)
}

// ── JVN 脆弱性 ─────────────────────────────────────────────

export interface JvnAffectedProduct {
  vendor: string
  product: string
  cpe: string
}

export interface JvnVulnerabilityOut {
  jvndb_id: string
  title: string
  overview: string
  cve_ids: string[]
  severity: string | null
  cvss_score: number | null
  cvss_vector: string | null
  affected_products: JvnAffectedProduct[]
  references: Record<string, string>[]
  jvn_url: string
  date_published: string
  date_last_modified: string
}

export interface JvnSeverityStat {
  severity: string
  count: number
}

export interface JvnStatsResponse {
  total: number
  severities: JvnSeverityStat[]
  monthly_trend: MonthlyStat[]
}

export interface JvnListResponse {
  total: number
  page: number
  per_page: number
  data: JvnVulnerabilityOut[]
}

export async function fetchJvnList(params: {
  page?: number
  perPage?: number
  days?: number
  severity?: string | null
  search?: string
  sortBy?: 'modified' | 'cvss'
}): Promise<JvnListResponse> {
  const p = new URLSearchParams()
  p.set('page', String(params.page ?? 1))
  p.set('per_page', String(params.perPage ?? 50))
  p.set('days', String(params.days ?? 180))
  if (params.severity) p.set('severity', params.severity)
  if (params.search) p.set('search', params.search)
  if (params.sortBy) p.set('sort_by', params.sortBy)
  return apiFetch<JvnListResponse>(`/api/jvn?${p}`)
}

export async function fetchJvnStats(days = 180): Promise<JvnStatsResponse> {
  return apiFetch<JvnStatsResponse>(`/api/jvn/stats?days=${days}`)
}

// ── DEPSCAN（自作アプリの依存ライブラリ脆弱性） ──────────────────

export interface DependencyFindingOut {
  repo_full_name: string
  ecosystem: string
  package_name: string
  installed_version: string
  osv_id: string
  severity: string | null
  cvss_score: number | null
  summary: string
  fixed_versions: string[]
  manifest_path: string
  detected_at: string
  resolved_at: string | null
}

export interface DepscanRepoStat {
  repo_full_name: string
  count: number
}

export interface DepscanSeverityStat {
  severity: string
  count: number
}

export interface DepscanStatsResponse {
  total: number
  repos: DepscanRepoStat[]
  severities: DepscanSeverityStat[]
}

export interface DepscanListResponse {
  total: number
  page: number
  per_page: number
  data: DependencyFindingOut[]
}

export async function fetchDepscanList(params: {
  page?: number
  perPage?: number
  owner?: string | null
  severity?: string | null
  resolved?: boolean | null
  authToken?: string
}): Promise<DepscanListResponse> {
  const p = new URLSearchParams()
  p.set('page', String(params.page ?? 1))
  p.set('per_page', String(params.perPage ?? 50))
  if (params.owner) p.set('owner', params.owner)
  if (params.severity) p.set('severity', params.severity)
  if (params.resolved !== null && params.resolved !== undefined) {
    p.set('resolved', String(params.resolved))
  }
  return apiFetch<DepscanListResponse>(`/api/depscan?${p}`, params.authToken)
}

export async function fetchDepscanStats(authToken?: string): Promise<DepscanStatsResponse> {
  return apiFetch<DepscanStatsResponse>('/api/depscan/stats', authToken)
}

// サーバー側は「パッケージ×CVE」単位で1件として返すため、パッケージ単位に
// 集約して表示するには該当するデータを全件取得してからクライアント側でグルーピングする
// 必要がある（API の最大 per_page=200 でページングしながら全件取得）。
const MAX_PER_PAGE = 200

export async function fetchAllDepscanFindings(params: {
  owner?: string | null
  severity?: string | null
  resolved?: boolean | null
  authToken?: string
}): Promise<DependencyFindingOut[]> {
  const first = await fetchDepscanList({ ...params, page: 1, perPage: MAX_PER_PAGE })
  const all = [...first.data]
  const totalPages = Math.ceil(first.total / MAX_PER_PAGE)
  for (let page = 2; page <= totalPages; page++) {
    const next = await fetchDepscanList({ ...params, page, perPage: MAX_PER_PAGE })
    all.push(...next.data)
  }
  return all
}

// ── DEPSCAN ダッシュボード用 GitHub ログイン（Issue #107） ────────────

export interface ScanStatusResponse {
  username: string
  status: 'not_started' | 'running' | 'done' | 'error'
  repos_scanned?: number
  started_at?: string
  finished_at?: string | null
  error_message?: string | null
}

// GitHub OAuth 認可画面へのリダイレクト先 URL（そのまま <a href> に指定する）
export function githubLoginUrl(): string {
  return `${BASE_URL}/auth/github/login`
}

// セッショントークンが無効・期限切れの場合（401）を、それ以外のエラー
// （ネットワーク瞬断・サーバー一時エラー等）と区別するための専用エラー型。
// 呼び出し側は Unauthorized のみをログアウトのトリガーとして扱うべきで、
// それ以外の一時的なエラーでユーザーを毎回ログアウトさせてはならない。
export class UnauthorizedError extends Error {}

// ログイン中ユーザーのオンデマンドスキャン進捗を取得する
export async function fetchScanStatus(authToken: string): Promise<ScanStatusResponse> {
  const res = await fetch(`${BASE_URL}/auth/scan-status`, {
    headers: { Authorization: `Bearer ${authToken}` },
  })
  if (res.status === 401) throw new UnauthorizedError('Session token is invalid or expired')
  if (!res.ok) throw new Error(`Scan status error ${res.status}`)
  return res.json()
}
