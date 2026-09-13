import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fetchDepscanList, fetchDepscanStats, fetchAllDepscanFindings, type DepscanListResponse } from './depscan'

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
})
