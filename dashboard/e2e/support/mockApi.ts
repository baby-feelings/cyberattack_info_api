import type { Page, Route } from '@playwright/test'
import {
  codescanItems, codescanStats, depscanFindings, depscanStats, depsopsItems,
  jvnItems, jvnStats, kevItems, kevStats, osvItems, osvStats, repoDependencies, repoRuntimes,
  runtimeReleases, slaOverdue, slaPolicy, slaRepos,
} from './mockData'

// バックエンドAPIのモック。全リクエストは `/__api` 配下（playwright.config.ts の
// VITE_API_BASE_URL）に向くため、page.route で一括して傍受し、実APIの
// クエリ（検索・フィルター・ページ）に反応する本物らしいレスポンスを返す。

export const API_PREFIX = '/__api'

export interface RecordedRequest {
  method: string
  path: string
  query: URLSearchParams
  headers: Record<string, string>
  body: unknown
}

export interface MockResponse {
  status?: number
  body?: unknown
}

export type MockHandler = (req: RecordedRequest) => MockResponse | undefined

export interface MockState {
  health: { status: 'ok' | 'degraded'; environment: string; db_connected: boolean }
  // DEPSCANスキャン進捗。先頭から順に返し、最後の要素は繰り返し返す
  scanStatuses: Array<Record<string, unknown>>
  // 最新のDEPSCANクロールログID（更新バナー検知用）
  crawlerLogId: number
  // Slack通知設定（GET/PUT/DELETE で読み書きされる）
  notification: { slack_webhook_url: string | null; notifications_enabled: boolean }
  // MCPトークンの台帳（POST で追加・GET で一覧・DELETE で失効）
  mcpTokens: Array<{
    id: string; created_at: string; expires_at: string
    revoked_at: string | null; last_used_at: string | null
    status: 'active' | 'revoked' | 'expired'
  }>
  // OAuth（MCP）で接続中のクライアント（GET で一覧・DELETE で解除）
  oauthConnections: Array<{
    client_id: string; client_name: string
    connected_at: string | null; last_refreshed_at: string | null
    last_used_at: string | null; expires_at: string | null
  }>
  // 運用停止中のリポジトリ（バックエンドの INACTIVE_REPOS 相当）。既定は空＝すべて運用中
  inactiveRepos: string[]
  username: string
}

export interface MockApi {
  state: MockState
  requests: RecordedRequest[]
  // 特定パスへのリクエストを新しい順でなく発生順に返す
  requestsTo: (path: string, method?: string) => RecordedRequest[]
  // 直近の特定パスへのリクエストのクエリ
  lastQuery: (path: string) => URLSearchParams | undefined
  // 既定のレスポンスを差し替える（後から登録したものが優先される）
  override: (method: string, path: string, handler: MockHandler) => void
}

function paginate<T>(items: T[], query: URLSearchParams, defaultPerPage: number) {
  const page = Number(query.get('page') ?? 1)
  const perPage = Number(query.get('per_page') ?? defaultPerPage)
  return {
    total: items.length,
    page,
    per_page: perPage,
    data: items.slice((page - 1) * perPage, page * perPage),
  }
}

// `operating=active|inactive|all`（未指定は all）に合わせて、リポジトリを残すかを返す。実APIと同じ振る舞い
function operatingKeep(query: URLSearchParams, state: MockState): (repo: string) => boolean {
  const operating = query.get('operating') ?? 'all'
  const inactive = new Set(state.inactiveRepos.map((r) => r.toLowerCase()))
  return (repo) => operating === 'all' || (inactive.has(repo.toLowerCase()) === (operating === 'inactive'))
}

const includesCI = (haystack: string, needle: string) =>
  haystack.toLowerCase().includes(needle.toLowerCase())

// 既定ハンドラー: 実APIと同様にクエリパラメータでデータを絞り込む
function defaultResponse(req: RecordedRequest, state: MockState): MockResponse {
  const { path, query, method } = req

  // パスに可変部分（トークンID）を含むため、switch の前で処理する
  if (method === 'DELETE' && path.startsWith('/auth/mcp-tokens/')) {
    const row = state.mcpTokens.find((t) => t.id === decodeURIComponent(path.split('/').pop()!))
    if (!row) return { status: 404, body: { detail: 'Token not found.' } }
    row.status = 'revoked'
    row.revoked_at = '2026-10-10T01:00:00+00:00'
    return { body: { id: row.id, revoked: true } }
  }

  if (method === 'DELETE' && path.startsWith('/auth/oauth-connections/')) {
    const id = decodeURIComponent(path.split('/').pop()!)
    const index = state.oauthConnections.findIndex((c) => c.client_id === id)
    if (index < 0) return { status: 404, body: { detail: 'Connection not found.' } }
    state.oauthConnections.splice(index, 1)
    return { body: { client_id: id, disconnected: true } }
  }

  switch (`${method} ${path}`) {
    case 'GET /health':
      return { body: state.health }

    // ── KEV ──
    case 'GET /api/vulnerabilities/recent': {
      // 実APIと同じく、過去 days 日以内に追加されたもの（モックは1日1件ずつ追加されている）
      const days = Number(query.get('days') ?? 30)
      return { body: kevItems.filter((_, i) => i <= days) }
    }
    case 'GET /api/vulnerabilities/stats':
      return { body: kevStats() }
    case 'GET /api/vulnerabilities': {
      const search = query.get('search')
      const minEpss = query.get('min_epss')
      const items = kevItems.filter((v) =>
        (!search || includesCI(v.vendor_project, search) || includesCI(v.product, search)
          || includesCI(v.cve_id, search))
        && (minEpss === null || (v.epss_score ?? -1) >= Number(minEpss)))
      return { body: paginate(items, query, 50) }
    }

    // ── OSV ──
    case 'GET /api/osv/stats':
      return { body: osvStats() }
    case 'GET /api/osv': {
      const eco = query.get('ecosystem')
      const sev = query.get('severity')
      const search = query.get('search')
      let items = osvItems.filter((v) =>
        (!eco || v.ecosystem === eco)
        && (!sev || v.severity === sev)
        && (!search || includesCI(v.osv_id, search) || includesCI(v.package_name, search)
          || includesCI(v.summary, search)))
      if (query.get('sort_by') === 'cvss') {
        items = [...items].sort((a, b) => (b.cvss_score ?? -1) - (a.cvss_score ?? -1))
      }
      return { body: paginate(items, query, 50) }
    }

    // ── JVN ──
    case 'GET /api/jvn/stats':
      return { body: jvnStats() }
    case 'GET /api/jvn': {
      const sev = query.get('severity')
      const search = query.get('search')
      let items = jvnItems.filter((v) =>
        (!sev || v.severity === sev)
        && (!search || includesCI(v.jvndb_id, search) || includesCI(v.title, search)
          || includesCI(v.overview, search)))
      if (query.get('sort_by') === 'cvss') {
        items = [...items].sort((a, b) => (b.cvss_score ?? -1) - (a.cvss_score ?? -1))
      }
      return { body: paginate(items, query, 50) }
    }

    // ── DEPSCAN ──
    case 'GET /api/depscan/stats':
      return { body: depscanStats(operatingKeep(query, state)) }
    case 'GET /api/depscan': {
      const owner = query.get('owner')
      const sev = query.get('severity')
      const resolved = query.get('resolved')
      const keep = operatingKeep(query, state)
      const items = depscanFindings.filter((f) =>
        keep(f.repo_full_name)
        && (!owner || f.repo_full_name.startsWith(`${owner}/`))
        && (!sev || f.severity === sev)
        && (resolved === null || (resolved === 'true') === !!f.resolved_at))
      return { body: paginate(items, query, 50) }
    }

    case 'GET /api/depscan/dependencies/repos': {
      const keep = operatingKeep(query, state)
      const repos = new Map<string, { total: number; vulnerable: number }>()
      for (const d of repoDependencies.filter((x) => keep(x.repo_full_name))) {
        const stat = repos.get(d.repo_full_name) ?? { total: 0, vulnerable: 0 }
        stat.total += 1
        if (d.open_vulnerabilities > 0) stat.vulnerable += 1
        repos.set(d.repo_full_name, stat)
      }
      // 実APIと同じく、検知がある（対応が必要な）アプリを先頭に、同数ならアプリ名順
      const sorted = [...repos].sort(([a, x], [b, y]) => y.vulnerable - x.vulnerable || a.localeCompare(b))
      return { body: { repos: sorted.map(([repo_full_name, s]) => ({ repo_full_name, ...s })) } }
    }
    case 'GET /api/depscan/dependencies': {
      const pkg = query.get('package')
      const version = query.get('version')
      const ecosystem = query.get('ecosystem')
      const repo = query.get('repo')
      const vulnerable = query.get('vulnerable') === 'true'
      const keep = operatingKeep(query, state)
      const items = repoDependencies.filter((d) =>
        keep(d.repo_full_name)
        && (!pkg || includesCI(d.package_name, pkg))
        && (!version || d.version === version)
        && (!ecosystem || d.ecosystem === ecosystem)
        && (!repo || d.repo_full_name === repo)
        && (!vulnerable || d.open_vulnerabilities > 0))
      return { body: paginate(items, query, 50) }
    }

    // ── SLA（脆弱性への対応状況。期限超過・平均対応日数）──
    case 'GET /api/sla': {
      const keep = operatingKeep(query, state)
      const overdue = slaOverdue.filter((i) => keep(i.repo_full_name))
      const repos = slaRepos.filter((r) => keep(r.repo_full_name))
      const resolved = repos.reduce((n, r) => n + r.resolved, 0)
      return {
        body: {
          generated_at: '2026-10-10T00:00:00+00:00',
          mttr_window_days: 90,
          policy: slaPolicy,
          summary: {
            open_with_deadline: repos.reduce((n, r) => n + r.open, 0),
            overdue: overdue.length,
            resolved,
            mttr_days: resolved > 0 ? 7.2 : null,
          },
          by_severity: [
            { severity: 'CRITICAL', deadline_days: 7, open: 1, overdue: 1, resolved: 0, mttr_days: null },
            { severity: 'HIGH', deadline_days: 30, open: 2, overdue: 1, resolved: 4, mttr_days: 7.2 },
            { severity: 'LOW', deadline_days: null, open: 1, overdue: 0, resolved: 0, mttr_days: null },
          ],
          by_repo: repos,
          overdue,
        },
      }
    }

    // ── RUNTIME（言語・実行環境のバージョン監視）──
    case 'GET /api/runtimes/repos': {
      const keep = operatingKeep(query, state)
      const actionable = new Set(['eol', 'eol_soon', 'update_available'])
      const repos = new Map<string, { total: number; needs_action: number }>()
      for (const r of repoRuntimes.filter((x) => keep(x.repo_full_name))) {
        const stat = repos.get(r.repo_full_name) ?? { total: 0, needs_action: 0 }
        stat.total += 1
        if (actionable.has(r.state)) stat.needs_action += 1
        repos.set(r.repo_full_name, stat)
      }
      // 実APIと同じく、対応が必要な数が多いアプリを先頭に、同数ならアプリ名順
      const sorted = [...repos].sort(([a, x], [b, y]) => y.needs_action - x.needs_action || a.localeCompare(b))
      return { body: { repos: sorted.map(([repo_full_name, s]) => ({ repo_full_name, ...s })) } }
    }
    case 'GET /api/runtimes/releases':
      return { body: { data: runtimeReleases } }
    case 'GET /api/runtimes': {
      const repo = query.get('repo')
      const runtime = query.get('runtime')
      const needsAction = query.get('needs_action') === 'true'
      const actionable = new Set(['eol', 'eol_soon', 'update_available'])
      const keep = operatingKeep(query, state)
      const items = repoRuntimes.filter((r) =>
        keep(r.repo_full_name)
        && (!repo || r.repo_full_name === repo)
        && (!runtime || r.runtime === runtime)
        && (!needsAction || actionable.has(r.state)))
      return { body: { total: items.length, data: items } }
    }

    // ── DEPSOPS ──
    case 'GET /api/depsops/stats': {
      const repos = new Map<string, number>()
      const keep = operatingKeep(query, state)
      for (const i of depsopsItems.filter((d) => d.action === 'flagged' && keep(d.repo_full_name))) {
        repos.set(i.repo_full_name, (repos.get(i.repo_full_name) ?? 0) + 1)
      }
      return { body: { repos: [...repos].map(([repo_full_name, count]) => ({ repo_full_name, count })) } }
    }
    case 'GET /api/depsops': {
      const action = query.get('action')
      const keep = operatingKeep(query, state)
      const items = depsopsItems.filter((d) => keep(d.repo_full_name) && (!action || d.action === action))
      return { body: paginate(items, query, 50) }
    }

    // ── クローラーログ ──
    case 'GET /api/crawler-logs':
      return {
        body: [{
          id: state.crawlerLogId, crawler_type: 'DEPSCAN', status: 'success',
          started_at: '2026-09-20T22:00:00Z', finished_at: '2026-09-20T22:01:00Z',
          duration_seconds: 60, inserted: 0, updated: 0, deleted: 0, error_message: null,
        }],
      }

    // ── CODESCAN ──
    case 'GET /api/codescan/stats':
      return { body: codescanStats(operatingKeep(query, state)) }
    case 'GET /api/codescan': {
      const sev = query.get('severity')
      const repo = query.get('repo')
      const resolved = query.get('resolved')
      const keep = operatingKeep(query, state)
      const items = codescanItems.filter((f) =>
        keep(f.repo_full_name)
        && (!repo || f.repo_full_name === repo)
        && (!sev || f.severity === sev)
        && (resolved === null || (resolved === 'true') === !!f.resolved_at))
      return { body: paginate(items, query, 30) }
    }

    // ── 認証・設定 ──
    case 'GET /auth/scan-status': {
      const next = state.scanStatuses.length > 1
        ? state.scanStatuses.shift()!
        : state.scanStatuses[0]
      return { body: next }
    }
    case 'POST /auth/exchange':
      return { body: { token: 'exchanged-token', username: state.username } }
    case 'POST /auth/refresh':
      // 実サーバーは新しいJWTを返すが、他のシナリオが Bearer の値を検証しているため、
      // 受け取ったトークンをそのまま返す（延長されたことの検証は専用シナリオで上書きする）
      return {
        body: {
          token: (req.headers['authorization'] ?? '').replace(/^Bearer /i, ''),
          username: state.username,
        },
      }
    case 'GET /auth/notification-settings':
      return { body: state.notification }
    case 'PUT /auth/notification-settings': {
      const url = (req.body as { slack_webhook_url: string }).slack_webhook_url
      state.notification = { slack_webhook_url: url, notifications_enabled: true }
      return { body: state.notification }
    }
    case 'POST /auth/mcp-token': {
      const days = (req.body as { days?: number } | null)?.days ?? 30
      const row = {
        id: `tok-${state.mcpTokens.length + 1}-aaaa-bbbb`,
        created_at: '2026-10-10T00:00:00+00:00',
        // 7日=2026-10-17 / 30日=2026-11-09 / 90日=2027-01-08（テストで期限選択を判別できる値）
        expires_at: { 7: '2026-10-17', 30: '2026-11-09', 90: '2027-01-08' }[days] + 'T00:00:00+00:00',
        revoked_at: null, last_used_at: null, status: 'active' as const,
      }
      state.mcpTokens.unshift(row)
      return { body: { ...row, token: 'mcp-test-token', username: state.username } }
    }
    case 'GET /auth/mcp-tokens':
      return { body: { tokens: state.mcpTokens } }
    case 'GET /auth/oauth-connections':
      return { body: { connections: state.oauthConnections } }
    case 'DELETE /auth/notification-settings':
      state.notification = { slack_webhook_url: null, notifications_enabled: false }
      return { body: state.notification }

    default:
      return { status: 404, body: { detail: `unmocked: ${method} ${path}` } }
  }
}

export async function installMockApi(page: Page): Promise<MockApi> {
  const state: MockState = {
    health: { status: 'ok', environment: 'production', db_connected: true },
    scanStatuses: [{ username: 'octocat', status: 'done', repos_scanned: 3 }],
    crawlerLogId: 100,
    notification: { slack_webhook_url: null, notifications_enabled: false },
    mcpTokens: [],
    oauthConnections: [],
    inactiveRepos: [],
    username: 'octocat',
  }
  const requests: RecordedRequest[] = []
  const overrides = new Map<string, MockHandler[]>()

  await page.route(`**${API_PREFIX}/**`, async (route: Route) => {
    const request = route.request()
    const url = new URL(request.url())
    let body: unknown = null
    const raw = request.postData()
    if (raw) {
      try { body = JSON.parse(raw) } catch { body = raw }
    }
    const req: RecordedRequest = {
      method: request.method(),
      path: url.pathname.slice(API_PREFIX.length),
      query: url.searchParams,
      headers: request.headers(),
      body,
    }
    requests.push(req)

    // 後から登録したオーバーライドを優先し、undefined を返したら次の候補へ進む
    const handlers = overrides.get(`${req.method} ${req.path}`) ?? []
    let response: MockResponse | undefined
    for (let i = handlers.length - 1; i >= 0 && !response; i--) response = handlers[i](req)
    response ??= defaultResponse(req, state)

    await route.fulfill({
      status: response.status ?? 200,
      contentType: 'application/json',
      body: JSON.stringify(response.body ?? null),
    })
  })

  return {
    state,
    requests,
    requestsTo: (path, method = 'GET') =>
      requests.filter((r) => r.path === path && r.method === method),
    lastQuery: (path) => requests.filter((r) => r.path === path).at(-1)?.query,
    override: (method, path, handler) => {
      const key = `${method} ${path}`
      overrides.set(key, [...(overrides.get(key) ?? []), handler])
    },
  }
}
