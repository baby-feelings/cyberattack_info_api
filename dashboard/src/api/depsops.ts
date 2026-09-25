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

export interface DepsOpsRepoStat {
  repo_full_name: string
  count: number
}

export interface DepsOpsStatsResponse {
  repos: DepsOpsRepoStat[]
}

// リポジトリ別の未解決PR件数（棒グラフ表示用）。以前はページングしながら
// 全件（2000件超）をクライアントに転送して集計していたが、履歴が増えるたびに
// 往復回数が増えて表示が遅くなっていた（10秒近くかかっていた）ため、
// 「(repo, pr_number) ごとの最新状態のみ数える」集計自体をサーバー側（SQL の
// ROW_NUMBER()）に移し、1回のリクエストで済むようにした
export async function fetchDepsOpsStats(): Promise<DepsOpsStatsResponse> {
  return apiFetch<DepsOpsStatsResponse>('/api/depsops/stats')
}
