import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  fetchDepscanList, fetchDepscanStats, fetchAllDepscanFindings, fetchRepoDependencies, fetchRepoDependencyRepos,
  type DepscanListResponse,
} from './depscan'

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    json: () => Promise.resolve(body),
  } as Response
}

describe('api/depscan', () => {
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  describe('fetchDepscanList', () => {
    it('sends the session token as Authorization when authToken is given', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, page: 1, per_page: 50, data: [] }))
      await fetchDepscanList({ authToken: 'session-token-abc' })
      const [, opts] = fetchMock.mock.calls[0]
      expect(opts.headers).toEqual({ Authorization: 'Bearer session-token-abc' })
    })

    it('omits owner/severity/resolved when not set', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, page: 1, per_page: 50, data: [] }))
      await fetchDepscanList({})
      const [url] = fetchMock.mock.calls[0]
      expect(url).not.toContain('owner=')
      expect(url).not.toContain('severity=')
      expect(url).not.toContain('resolved=')
    })

    it('includes owner and severity filters when provided', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, page: 1, per_page: 50, data: [] }))
      await fetchDepscanList({ owner: 'baby-feelings', severity: 'HIGH' })
      const [url] = fetchMock.mock.calls[0]
      expect(url).toContain('owner=baby-feelings')
      expect(url).toContain('severity=HIGH')
    })

    it('includes resolved=false explicitly (not omitted like null)', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, page: 1, per_page: 50, data: [] }))
      await fetchDepscanList({ resolved: false })
      const [url] = fetchMock.mock.calls[0]
      expect(url).toContain('resolved=false')
    })
  })

  describe('fetchDepscanStats', () => {
    it('uses X-API-KEY when no authToken is provided', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, repos: [], severities: [] }))
      await fetchDepscanStats()
      const [, opts] = fetchMock.mock.calls[0]
      expect(opts.headers).toHaveProperty('X-API-KEY')
    })

    it('sends the session token as Authorization when authToken is given', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, repos: [], severities: [] }))
      await fetchDepscanStats('session-token-abc')
      const [, opts] = fetchMock.mock.calls[0]
      expect(opts.headers).toEqual({ Authorization: 'Bearer session-token-abc' })
    })
  })

  describe('fetchAllDepscanFindings', () => {
    const page = (data: DepscanListResponse['data'], total: number, per_page = 200) =>
      jsonResponse({ total, page: 1, per_page, data })

    it('returns all items when everything fits on one page', async () => {
      const items = [{ osv_id: 'GHSA-1' }] as DepscanListResponse['data']
      fetchMock.mockResolvedValueOnce(page(items, 1))
      const all = await fetchAllDepscanFindings({})
      expect(all).toEqual(items)
      expect(fetchMock).toHaveBeenCalledTimes(1)
    })

    it('pages through multiple requests when total exceeds one page', async () => {
      const firstPage = Array.from({ length: 200 }, (_, i) => ({ osv_id: `GHSA-${i}` })) as DepscanListResponse['data']
      const secondPage = [{ osv_id: 'GHSA-200' }] as DepscanListResponse['data']
      fetchMock
        .mockResolvedValueOnce(page(firstPage, 201))
        .mockResolvedValueOnce(page(secondPage, 201))

      const all = await fetchAllDepscanFindings({})
      expect(all).toHaveLength(201)
      expect(fetchMock).toHaveBeenCalledTimes(2)
    })
  })

  describe('operating status filter', () => {
    it('sends operating on the list request only for active / inactive', async () => {
      fetchMock.mockResolvedValue(jsonResponse({ total: 0, page: 1, per_page: 30, data: [] }))
      await fetchDepscanList({ operating: 'active' })
      expect(fetchMock.mock.calls[0][0]).toContain('operating=active')
      await fetchDepscanList({ operating: 'inactive' })
      expect(fetchMock.mock.calls[1][0]).toContain('operating=inactive')
      await fetchDepscanList({ operating: 'all' })
      expect(fetchMock.mock.calls[2][0]).not.toContain('operating=')
      await fetchDepscanList({})
      expect(fetchMock.mock.calls[3][0]).not.toContain('operating=')
    })

    it('sends operating on the stats request', async () => {
      fetchMock.mockResolvedValue(jsonResponse({ total: 0, repos: [], severities: [] }))
      await fetchDepscanStats(undefined, 'inactive')
      expect(fetchMock.mock.calls[0][0]).toContain('/api/depscan/stats?operating=inactive')
    })
  })
  describe('fetchRepoDependencies', () => {
    it('sends the search conditions and the session token', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, page: 1, per_page: 20, data: [] }))
      await fetchRepoDependencies({
        page: 2, perPage: 20, packageName: 'undici', version: '8.11.2', ecosystem: 'npm',
        repo: 'baby-feelings/app-one', vulnerableOnly: true, operating: 'active',
        authToken: 'session-token-abc',
      })
      const [url, opts] = fetchMock.mock.calls[0]
      const query = new URL(url, 'http://localhost').searchParams
      expect(new URL(url, 'http://localhost').pathname).toMatch(/\/api\/depscan\/dependencies$/)
      expect(query.get('page')).toBe('2')
      expect(query.get('per_page')).toBe('20')
      expect(query.get('package')).toBe('undici')
      expect(query.get('version')).toBe('8.11.2')
      expect(query.get('ecosystem')).toBe('npm')
      expect(query.get('repo')).toBe('baby-feelings/app-one')
      expect(query.get('vulnerable')).toBe('true')
      expect(query.get('operating')).toBe('active')
      expect(opts.headers).toEqual({ Authorization: 'Bearer session-token-abc' })
    })

    it('trims the input and omits empty conditions', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, page: 1, per_page: 50, data: [] }))
      await fetchRepoDependencies({ packageName: '  undici  ', version: '   ', ecosystem: null })
      const [url] = fetchMock.mock.calls[0]
      const query = new URL(url, 'http://localhost').searchParams
      expect(query.get('package')).toBe('undici')
      expect(query.has('version')).toBe(false)
      expect(query.has('ecosystem')).toBe(false)
      expect(query.has('repo')).toBe(false)
      expect(query.has('vulnerable')).toBe(false)
      expect(query.has('operating')).toBe(false)
    })
  })

  describe('fetchRepoDependencyRepos', () => {
    it('requests the per-app counts with the operating filter and the session token', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ repos: [] }))
      await fetchRepoDependencyRepos('session-token-abc', 'inactive')
      const [url, opts] = fetchMock.mock.calls[0]
      const parsed = new URL(url, 'http://localhost')
      expect(parsed.pathname).toMatch(/\/api\/depscan\/dependencies\/repos$/)
      expect(parsed.searchParams.get('operating')).toBe('inactive')
      expect(opts.headers).toEqual({ Authorization: 'Bearer session-token-abc' })
    })
  })
})
