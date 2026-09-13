import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fetchCrawlerLogs } from './crawlerLogs'

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    json: () => Promise.resolve(body),
  } as Response
}

describe('api/crawlerLogs', () => {
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  describe('fetchCrawlerLogs', () => {
    it('includes crawler_type, status, and limit when provided', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse([]))
      await fetchCrawlerLogs({ crawlerType: 'DEPSCAN', status: 'success', limit: 1 })
      const [url] = fetchMock.mock.calls[0]
      expect(url).toContain('crawler_type=DEPSCAN')
      expect(url).toContain('status=success')
      expect(url).toContain('limit=1')
    })

    it('defaults limit to 30 when omitted', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse([]))
      await fetchCrawlerLogs({})
      const [url] = fetchMock.mock.calls[0]
      expect(url).toContain('limit=30')
    })

    it('omits crawler_type/status when not provided', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse([]))
      await fetchCrawlerLogs({})
      const [url] = fetchMock.mock.calls[0]
      expect(url).not.toContain('crawler_type=')
      expect(url).not.toContain('status=')
    })
  })
})
