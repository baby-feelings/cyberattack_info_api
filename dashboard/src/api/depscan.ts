// DEPSCAN（自作アプリの依存ライブラリ脆弱性）関連の API クライアント。

import { DEFAULT_PER_PAGE, apiFetch, withOperating, type OperatingStatus } from './shared'

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
  // 悪意あるパッケージ（OSV IDが MAL-*）か。脆弱性ではなくマルウェアで、更新ではなく
  // 削除と認証情報の再発行が必要（Issue #399）
  is_malicious: boolean
  // 優先度判定に寄与した要因（Issue #135）。kev_listed/epss_high/reachable/
  // public_repo/internet_facing_asset/production_asset/high_importance_asset/malicious_package
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
  operating?: OperatingStatus
  authToken?: string
}): Promise<DepscanListResponse> {
  const p = new URLSearchParams()
  p.set('page', String(params.page ?? 1))
  p.set('per_page', String(params.perPage ?? DEFAULT_PER_PAGE))
  if (params.owner) p.set('owner', params.owner)
  if (params.operating && params.operating !== 'all') p.set('operating', params.operating)
  if (params.severity) p.set('severity', params.severity)
  if (params.resolved !== null && params.resolved !== undefined) {
    p.set('resolved', String(params.resolved))
  }
  return apiFetch<DepscanListResponse>(`/api/depscan?${p}`, params.authToken)
}

// 使っている依存パッケージ（SBOM の全量）の横断検索。「どのリポジトリが、そのパッケージの
// どの版を使っているか」を引く（新しい脆弱性の影響範囲の確認用）
export interface RepoDependencyOut {
  repo_full_name: string
  ecosystem: string
  package_name: string
  version: string
  manifest_path: string
  scanned_at: string
  purl: string | null
  // この版に対する未解決の検知件数（0なら検知なし）
  open_vulnerabilities: number | null
}

export interface RepoDependencyListResponse {
  total: number
  page: number
  per_page: number
  data: RepoDependencyOut[]
}

export async function fetchRepoDependencies(params: {
  page?: number
  perPage?: number
  packageName?: string
  version?: string
  ecosystem?: string | null
  // 指定したリポジトリ（owner/repo）の依存だけ。null = すべて
  repo?: string | null
  // 未解決の検知がある依存だけ
  vulnerableOnly?: boolean
  operating?: OperatingStatus
  authToken?: string
}): Promise<RepoDependencyListResponse> {
  const p = new URLSearchParams()
  p.set('page', String(params.page ?? 1))
  p.set('per_page', String(params.perPage ?? DEFAULT_PER_PAGE))
  // 前後の空白は検索の邪魔になるだけなので除く
  if (params.packageName?.trim()) p.set('package', params.packageName.trim())
  if (params.version?.trim()) p.set('version', params.version.trim())
  if (params.ecosystem) p.set('ecosystem', params.ecosystem)
  if (params.repo) p.set('repo', params.repo)
  if (params.vulnerableOnly) p.set('vulnerable', 'true')
  if (params.operating && params.operating !== 'all') p.set('operating', params.operating)
  return apiFetch<RepoDependencyListResponse>(`/api/depscan/dependencies?${p}`, params.authToken)
}

// リポジトリごとの、使っている依存の数と、うち未解決の検知がある依存の数
// （依存パッケージの閲覧画面の、左のリポジトリ一覧用。対応が必要なリポジトリが先頭）
export interface RepoDependencyRepoStat {
  repo_full_name: string
  total: number
  vulnerable: number
}

export interface RepoDependencyRepoListResponse {
  repos: RepoDependencyRepoStat[]
}

export async function fetchRepoDependencyRepos(
  authToken?: string, operating?: OperatingStatus,
): Promise<RepoDependencyRepoListResponse> {
  return apiFetch<RepoDependencyRepoListResponse>(
    withOperating('/api/depscan/dependencies/repos', operating), authToken,
  )
}

export async function fetchDepscanStats(
  authToken?: string, operating?: OperatingStatus,
): Promise<DepscanStatsResponse> {
  return apiFetch<DepscanStatsResponse>(withOperating('/api/depscan/stats', operating), authToken)
}

// サーバー側は「パッケージ×CVE」単位で1件として返すため、パッケージ単位に
// 集約して表示するには該当するデータを全件取得してからクライアント側でグルーピングする
// 必要がある（API の最大 per_page=200 でページングしながら全件取得）。
const MAX_PER_PAGE = 200

export async function fetchAllDepscanFindings(params: {
  owner?: string | null
  severity?: string | null
  resolved?: boolean | null
  operating?: OperatingStatus
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
