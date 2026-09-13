// DEPSOPS（Dependabot PR 自動運用の判定履歴）関連の API クライアント。

import { apiFetch } from './shared'

export interface DependabotPrLogOut {
  repo_full_name: string
  pr_number: number
  title: string
  // "closed": 過去にflagged記録した後、DEPSOPS外の要因（Dependabotの自動クローズ・
  // 手動マージ等）で解消済みと判定されたことを示す（バックエンド参照）
  action: 'merged' | 'flagged' | 'closed'
  reason: string | null
  is_security_update: boolean | null
  compatibility_badge_url: string | null
  processed_at: string
}

export interface DepsOpsListResponse {
  total: number
  page: number
  per_page: number
  data: DependabotPrLogOut[]
}

export async function fetchDepsOpsList(params: {
  page?: number
  perPage?: number
  repo?: string | null
  action?: 'merged' | 'flagged' | 'closed' | null
}): Promise<DepsOpsListResponse> {
  const p = new URLSearchParams()
  p.set('page', String(params.page ?? 1))
  p.set('per_page', String(params.perPage ?? 50))
  if (params.repo) p.set('repo', params.repo)
  if (params.action) p.set('action', params.action)
  return apiFetch<DepsOpsListResponse>(`/api/depsops?${p}`)
}

// リポジトリ別件数の集計（未解決PRのチャート表示）には全件が必要なため、
// DEPSCANの fetchAllDepscanFindings と同じくページングしながら全件取得する
const DEPSOPS_MAX_PER_PAGE = 200

export async function fetchAllDepsOpsEntries(params: {
  repo?: string | null
  action?: 'merged' | 'flagged' | null
} = {}): Promise<DependabotPrLogOut[]> {
  const first = await fetchDepsOpsList({ ...params, page: 1, perPage: DEPSOPS_MAX_PER_PAGE })
  const all = [...first.data]
  const totalPages = Math.ceil(first.total / DEPSOPS_MAX_PER_PAGE)
  for (let page = 2; page <= totalPages; page++) {
    const next = await fetchDepsOpsList({ ...params, page, perPage: DEPSOPS_MAX_PER_PAGE })
    all.push(...next.data)
  }
  return all
}
