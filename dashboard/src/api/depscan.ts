// DEPSCAN（自作アプリの依存ライブラリ脆弱性）関連の API クライアント。

import { apiFetch } from './shared'

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
  reachability: 'reachable' | 'unreachable' | 'unknown' | null
  // GitHub APIの"private"フィールドから自動取得（Issue #131）。旧レコードはnull
  repo_visibility: 'public' | 'private' | null
  // 優先度判定に寄与した要因（Issue #135）。kev_listed/epss_high/reachable/
  // public_repo/internet_facing_asset/production_asset/high_importance_asset
  priority_reasons: string[]
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
