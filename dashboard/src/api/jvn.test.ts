import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fetchJvnList, fetchJvnStats } from './jvn'

const BASE_URL = 'https://cyberattack-info-api.onrender.com'

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    json: () => Promise.resolve(body),
  } as Response
}

describe('api/jvn', () => {
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  describe('fetchJvnList / fetchJvnStats', () => {
    it('includes severity and search when provided', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, page: 1, per_page: 50, data: [] }))
      await fetchJvnList({ severity: 'High', search: 'Apache' })
      const [url] = fetchMock.mock.calls[0]
      expect(url).toContain('severity=High')
      expect(url).toContain('search=Apache')
    })

    it('includes sort_by when provided and omits it otherwise', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, page: 1, per_page: 50, data: [] }))
      await fetchJvnList({ sortBy: 'cvss' })
      const [url] = fetchMock.mock.calls[0]
      expect(url).toContain('sort_by=cvss')
    })

    it('requests /api/jvn/stats with the given days', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, severities: [], monthly_trend: [] }))
      await fetchJvnStats(30)
      const [url] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/api/jvn/stats?days=30`)
    })

    it('defaults fetchJvnStats to 180 days', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, severities: [], monthly_trend: [] }))
      await fetchJvnStats()
      const [url] = fetchMock.mock.calls[0]
      expect(url).toContain('days=180')
    })
  })
})
