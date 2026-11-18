// 態勢（GitHub のセキュリティアラート・リポジトリ設定の監査・公開サイトの外形監視）の API クライアント。
// 3つとも、セッション認証時は本人所有のリポジトリだけが返る（サーバー側で絞り込む）。

import { apiFetch, withOperating, type OperatingStatus } from './shared'

// API のパス。画面の側に直書きしない
export const POSTURE_PATHS = {
  audit: '/api/repo-audit',
  alerts: '/api/github-alerts',
  sites: '/api/site-monitor',
} as const

// ── リポジトリ設定の監査 ────────────────────────────────────────────

// 点検項目1件。`label`・`fix` は API が返す（画面に項目名を持たない）。
// `status` は ok / ng / unavailable / not_enforceable。未知の値が来ても、画面側で安全に扱う
export interface AuditCheckOut {
  key: string
  label: string
  status: string
  weight: number
  detail: string
  fix: string
}

export interface RepoAuditOut {
  repo_full_name: string
  // 点検できた項目の達成率（0〜100）。点検できなかったリポジトリは null
  score: number | null
  // 不合格（ng）の項目数
  issues: number
  checks: AuditCheckOut[]
  changes: Record<string, unknown>[]
  audited_at: string
}

export interface RepoAuditResponse {
  total: number
  repos_with_issues: number
  data: RepoAuditOut[]
}

// ── GitHub のセキュリティアラート ──────────────────────────────────────

export interface GithubAlertOut {
  // secret / dependabot / code
  kind: string
  repo_full_name: string
  number: number
  severity: string | null
  title: string
  html_url: string
  // 種類ごとの追加情報（検知元のツール名など）。シークレットの値は含まれない
  detail: Record<string, unknown>
  detected_at: string
  resolved_at: string | null
}

// 取得できなかった項目（機能が無効・権限不足）
export interface UnavailableSource {
  kind: string
  repo_full_name: string
  reason: string | null
}

export interface GithubAlertListResponse {
  total: number
  data: GithubAlertOut[]
  unavailable: UnavailableSource[]
}

// ── 公開サイトの外形監視 ───────────────────────────────────────────

export interface SiteFindingOut {
  rule: string
  // ERROR / WARNING / INFO
  severity: string
  message: string
}

export interface SiteCheckOut {
  url: string
  source: string
  // リポジトリに紐づかないサイト（設定で指定した監視対象）は null
  repo_full_name: string | null
  tls_days_left: number | null
  // 問題（ERROR・WARNING）の数。INFO は含まない
  issues: number
  findings: SiteFindingOut[]
  checked_at: string
}

export interface SiteMonitorResponse {
  total: number
  sites_with_issues: number
  data: SiteCheckOut[]
}

// ── 取得 ──────────────────────────────────────────────────────────

// クエリ文字列を付けたパス（値が無ければ、`?` も付けない）
function withQuery(path: string, params: URLSearchParams): string {
  const query = params.toString()
  return query ? `${path}?${query}` : path
}

export async function fetchRepoAudit(params: {
  onlyIssues?: boolean
  operating?: OperatingStatus
  authToken?: string
}): Promise<RepoAuditResponse> {
  const p = new URLSearchParams()
  if (params.onlyIssues) p.set('only_issues', 'true')
  return apiFetch<RepoAuditResponse>(
    withOperating(withQuery(POSTURE_PATHS.audit, p), params.operating), params.authToken,
  )
}

export async function fetchGithubAlerts(params: {
  kind?: string | null
  repo?: string | null
  // 解決済みも含めるときだけ true。false・省略は、未解決のみ（API の既定）
  resolved?: boolean
  operating?: OperatingStatus
  authToken?: string
}): Promise<GithubAlertListResponse> {
  const p = new URLSearchParams()
  if (params.kind) p.set('kind', params.kind)
  if (params.repo) p.set('repo', params.repo)
  if (params.resolved) p.set('resolved', 'true')
  return apiFetch<GithubAlertListResponse>(
    withOperating(withQuery(POSTURE_PATHS.alerts, p), params.operating), params.authToken,
  )
}

export async function fetchSiteMonitor(params: {
  onlyIssues?: boolean
  operating?: OperatingStatus
  authToken?: string
}): Promise<SiteMonitorResponse> {
  const p = new URLSearchParams()
  if (params.onlyIssues) p.set('only_issues', 'true')
  return apiFetch<SiteMonitorResponse>(
    withOperating(withQuery(POSTURE_PATHS.sites, p), params.operating), params.authToken,
  )
}
