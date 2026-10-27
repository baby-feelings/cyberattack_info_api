// 言語・実行環境のバージョン監視（RUNTIME。Python・Node.js・Flutter・Dart）関連の API クライアント。
// 各アプリが使っている版と、最新版・サポート期限から判定した状態を取得する（バックエンドの /api/runtimes）。

import { apiFetch, type OperatingStatus } from './shared'

// 使っている版の状態。eol=サポート終了 / eol_soon=期限間近 / update_available=新しい系列あり /
// latest=推奨の系列 / reference=下限の指定のため参考 / unknown=リリース情報なし
export type RuntimeState =
  | 'eol' | 'eol_soon' | 'update_available' | 'latest' | 'reference' | 'unknown'

export interface RepoRuntimeOut {
  repo_full_name: string
  runtime: string
  runtime_label: string
  // 使っているバージョン系列（例: 3.13 / 24）
  cycle: string
  source_path: string
  // false は「この版以上」のような下限の指定（実際に動いている版とは限らない）
  pinned: boolean
  state: RuntimeState
  // 使っている系列の最新版
  latest_version: string | null
  recommended_cycle: string | null
  recommended_version: string | null
  eol_date: string | null
  days_to_eol: number | null
}

export interface RepoRuntimeListResponse {
  total: number
  data: RepoRuntimeOut[]
}

export async function fetchRuntimes(params: {
  // 指定したリポジトリ（owner/repo）だけ。null = すべて
  repo?: string | null
  // 言語（python / nodejs / flutter / dart）。null = すべて
  runtime?: string | null
  // 対応が必要なもの（期限切れ・期限間近・更新あり）だけ
  needsAction?: boolean
  operating?: OperatingStatus
  authToken?: string
}): Promise<RepoRuntimeListResponse> {
  const p = new URLSearchParams()
  if (params.repo) p.set('repo', params.repo)
  if (params.runtime) p.set('runtime', params.runtime)
  if (params.needsAction) p.set('needs_action', 'true')
  if (params.operating && params.operating !== 'all') p.set('operating', params.operating)
  const query = p.toString()
  return apiFetch<RepoRuntimeListResponse>(
    query ? `/api/runtimes?${query}` : '/api/runtimes', params.authToken,
  )
}

// リポジトリごとの、検出した数と、うち対応が必要な数（閲覧画面の、左のアプリ一覧用）
export interface RepoRuntimeRepoStat {
  repo_full_name: string
  total: number
  needs_action: number
}

export interface RepoRuntimeRepoListResponse {
  repos: RepoRuntimeRepoStat[]
}

export async function fetchRuntimeRepos(
  authToken?: string, operating?: OperatingStatus,
): Promise<RepoRuntimeRepoListResponse> {
  const query = operating && operating !== 'all' ? `?operating=${operating}` : ''
  return apiFetch<RepoRuntimeRepoListResponse>(`/api/runtimes/repos${query}`, authToken)
}

// 言語ごとの、バージョン系列の最新版とサポート期限
export interface RuntimeReleaseOut {
  runtime: string
  runtime_label: string
  cycle: string
  latest_version: string
  release_date: string | null
  eol_date: string | null
  is_eol: boolean
  is_lts: boolean
  // 推奨の系列か（サポート中で、公開から経った最新。Node.js は LTS のみ）
  recommended: boolean
}

export interface RuntimeReleaseListResponse {
  data: RuntimeReleaseOut[]
}

export async function fetchRuntimeReleases(authToken?: string): Promise<RuntimeReleaseListResponse> {
  return apiFetch<RuntimeReleaseListResponse>('/api/runtimes/releases', authToken)
}
