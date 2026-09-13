import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fetchDepsOpsList, fetchAllDepsOpsEntries, type DepsOpsListResponse } from './depsops'

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    json: () => Promise.resolve(body),
  } as Response
}

describe('api/depsops', () => {
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  describe('fetchDepsOpsList', () => {
    it('sends the X-API-KEY header and default pagination', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, page: 1, per_page: 50, data: [] }))
      await fetchDepsOpsList({})
      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toContain('/api/depsops?')
      expect(url).toContain('page=1')
      expect(url).toContain('per_page=50')
      expect(opts.headers).toHaveProperty('X-API-KEY')
    })

    it('omits repo/action when not set', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, page: 1, per_page: 50, data: [] }))
      await fetchDepsOpsList({})
      const [url] = fetchMock.mock.calls[0]
      expect(url).not.toContain('repo=')
      expect(url).not.toContain('action=')
    })

    it('includes repo and action filters when provided', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, page: 1, per_page: 50, data: [] }))
      await fetchDepsOpsList({ repo: 'baby-feelings/baby_grow', action: 'flagged' })
      const [url] = fetchMock.mock.calls[0]
      expect(url).toContain('repo=baby-feelings%2Fbaby_grow')
      expect(url).toContain('action=flagged')
    })
  })

  describe('fetchAllDepsOpsEntries', () => {
    const page = (data: DepsOpsListResponse['data'], total: number, per_page = 200) =>
      jsonResponse({ total, page: 1, per_page, data })

    it('returns all items when everything fits on one page', async () => {
      const items = [{ pr_number: 1 }] as DepsOpsListResponse['data']
      fetchMock.mockResolvedValueOnce(page(items, 1))
      const all = await fetchAllDepsOpsEntries()
      expect(all).toEqual(items)
      expect(fetchMock).toHaveBeenCalledTimes(1)
    })

    it('pages through multiple requests when total exceeds one page', async () => {
      const firstPage = Array.from({ length: 200 }, (_, i) => ({ pr_number: i })) as DepsOpsListResponse['data']
      const secondPage = [{ pr_number: 200 }] as DepsOpsListResponse['data']
      fetchMock
        .mockResolvedValueOnce(page(firstPage, 201))
        .mockResolvedValueOnce(page(secondPage, 201))
      const all = await fetchAllDepsOpsEntries()
      expect(all).toHaveLength(201)
      expect(fetchMock).toHaveBeenCalledTimes(2)
    })

    it('forwards repo/action filters to each page request', async () => {
      fetchMock.mockResolvedValueOnce(page([], 0))
      await fetchAllDepsOpsEntries({ repo: 'u/r', action: 'flagged' })
      const [url] = fetchMock.mock.calls[0]
      expect(url).toContain('repo=u%2Fr')
      expect(url).toContain('action=flagged')
    })
  })
})
