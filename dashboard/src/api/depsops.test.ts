import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fetchDepsOpsList, fetchDepsOpsStats } from './depsops'

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

  describe('fetchDepsOpsStats', () => {
    it('sends the X-API-KEY header and returns repo stats in one request', async () => {
      fetchMock.mockResolvedValueOnce(
        jsonResponse({ repos: [{ repo_full_name: 'u/r', count: 3 }] }),
      )
      const res = await fetchDepsOpsStats()
      expect(res.repos).toEqual([{ repo_full_name: 'u/r', count: 3 }])
      expect(fetchMock).toHaveBeenCalledTimes(1)
      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toContain('/api/depsops/stats')
      expect(opts.headers).toHaveProperty('X-API-KEY')
    })
  })
})
