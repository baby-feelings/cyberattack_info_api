// JVN（Japan Vulnerability Notes）関連の API クライアント。

import { apiFetch, type MonthlyStat } from './shared'

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
