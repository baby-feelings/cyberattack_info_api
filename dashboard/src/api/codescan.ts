// CODESCAN（自アプリのコード脆弱性診断）関連の API クライアント。

import { apiFetch } from './shared'

export interface CodeFindingOut {
  repo_full_name: string
  file_path: string
  line_start: number
  line_end: number
  rule_id: string
  message: string
  severity: string
  cwe_ids: string[]
  owasp_categories: string[]
  code_snippet: string
  cvss_score: number | null
  cvss_vector: string | null
  tool: string
  detected_at: string
  resolved_at: string | null
}

export interface CodescanRepoStat {
  repo_full_name: string
  count: number
}

export interface CodescanSeverityStat {
  severity: string
  count: number
}

export interface CodescanStatsResponse {
  total: number
  repos: CodescanRepoStat[]
  severities: CodescanSeverityStat[]
}

export interface CodescanListResponse {
  total: number
  page: number
  per_page: number
  data: CodeFindingOut[]
}

export async function fetchCodescanList(params: {
  page?: number
  perPage?: number
  repo?: string | null
  owner?: string | null
  severity?: string | null
  resolved?: boolean | null
  minCvss?: number | null
  authToken?: string
}): Promise<CodescanListResponse> {
  const p = new URLSearchParams()
  p.set('page', String(params.page ?? 1))
  p.set('per_page', String(params.perPage ?? 30))
  if (params.repo) p.set('repo', params.repo)
  if (params.owner) p.set('owner', params.owner)
  if (params.severity) p.set('severity', params.severity)
  if (params.resolved !== null && params.resolved !== undefined) {
    p.set('resolved', String(params.resolved))
  }
  if (params.minCvss !== null && params.minCvss !== undefined) {
    p.set('min_cvss', String(params.minCvss))
  }
  return apiFetch<CodescanListResponse>(`/api/codescan?${p}`, params.authToken)
}

export async function fetchCodescanStats(authToken?: string): Promise<CodescanStatsResponse> {
  return apiFetch<CodescanStatsResponse>('/api/codescan/stats', authToken)
}
