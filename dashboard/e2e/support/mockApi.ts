import type { Page, Route } from '@playwright/test'
import {
  codescanItems, codescanStats, depscanFindings, depscanStats, depsopsItems,
  jvnItems, jvnStats, kevItems, kevStats, osvItems, osvStats,
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

const includesCI = (haystack: string, needle: string) =>
  haystack.toLowerCase().includes(needle.toLowerCase())

// 既定ハンドラー: 実APIと同様にクエリパラメータでデータを絞り込む
function defaultResponse(req: RecordedRequest, state: MockState): MockResponse {
  const { path, query, method } = req

  switch (`${method} ${path}`) {
    case 'GET /health':
      return { body: state.health }

    // ── KEV ──
    case 'GET /api/vulnerabilities/recent':
      return { body: kevItems.slice(0, 3) }
    case 'GET /api/vulnerabilities/stats':
      return { body: kevStats() }
    case 'GET /api/vulnerabilities': {
      const search = query.get('search')
      const items = search
        ? kevItems.filter((v) =>
          includesCI(v.vendor_project, search) || includesCI(v.product, search)
          || includesCI(v.cve_id, search))
        : kevItems
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
      return { body: depscanStats() }
    case 'GET /api/depscan': {
      const owner = query.get('owner')
      const sev = query.get('severity')
      const resolved = query.get('resolved')
      const items = depscanFindings.filter((f) =>
        (!owner || f.repo_full_name.startsWith(`${owner}/`))
        && (!sev || f.severity === sev)
        && (resolved === null || (resolved === 'true') === !!f.resolved_at))
      return { body: paginate(items, query, 50) }
    }

    // ── DEPSOPS ──
    case 'GET /api/depsops/stats': {
      const repos = new Map<string, number>()
      for (const i of depsopsItems.filter((d) => d.action === 'flagged')) {
        repos.set(i.repo_full_name, (repos.get(i.repo_full_name) ?? 0) + 1)
      }
      return { body: { repos: [...repos].map(([repo_full_name, count]) => ({ repo_full_name, count })) } }
    }
    case 'GET /api/depsops': {
      const action = query.get('action')
      const items = depsopsItems.filter((d) => !action || d.action === action)
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
      return { body: codescanStats() }
    case 'GET /api/codescan': {
      const sev = query.get('severity')
      const resolved = query.get('resolved')
      const items = codescanItems.filter((f) =>
        (!sev || f.severity === sev)
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
    case 'GET /auth/notification-settings':
      return { body: state.notification }
    case 'PUT /auth/notification-settings': {
      const url = (req.body as { slack_webhook_url: string }).slack_webhook_url
      state.notification = { slack_webhook_url: url, notifications_enabled: true }
      return { body: state.notification }
    }
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
