// OSV（Open Source Vulnerabilities）関連の API クライアント。

import { apiFetch, type MonthlyStat } from './shared'

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
