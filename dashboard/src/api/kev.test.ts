import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fetchHealth, fetchRecent, fetchStats, fetchVulnerabilities } from './kev'

const BASE_URL = 'https://cyberattack-info-api.onrender.com'

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    json: () => Promise.resolve(body),
  } as Response
}

describe('api/kev', () => {
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  describe('fetchHealth', () => {
    it('calls /health without an API key header', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ status: 'ok', environment: 'production', db_connected: true }))
      const result = await fetchHealth()
      expect(result.status).toBe('ok')
      expect(fetchMock).toHaveBeenCalledWith(`${BASE_URL}/health`)
    })

    it('throws when the response is not ok', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 503 }))
      await expect(fetchHealth()).rejects.toThrow('Health check failed: 503')
    })
  })

  describe('fetchRecent / fetchStats', () => {
    it('requests /api/vulnerabilities/recent with the given days', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse([]))
      await fetchRecent(7)
      const [url] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/api/vulnerabilities/recent?days=7`)
    })

    it('defaults to 30 days when omitted', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse([]))
      await fetchRecent()
      const [url] = fetchMock.mock.calls[0]
      expect(url).toContain('days=30')
    })

    it('sends the X-API-KEY header for authenticated endpoints', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total_vulnerabilities: 0, top_vendors: [], monthly_trend: [] }))
      await fetchStats()
      const [, opts] = fetchMock.mock.calls[0]
      expect(opts.headers).toHaveProperty('X-API-KEY')
      expect(opts.headers).not.toHaveProperty('Authorization')
    })

    it('throws with the path included when the API errors', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 500 }))
      await expect(fetchStats()).rejects.toThrow('API error 500')
    })
  })

  describe('fetchVulnerabilities', () => {
    it('builds pagination and search query params', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, page: 1, per_page: 20, data: [] }))
      await fetchVulnerabilities({ page: 2, perPage: 20, search: 'Microsoft' })
      const [url] = fetchMock.mock.calls[0]
      expect(url).toContain('page=2')
      expect(url).toContain('per_page=20')
      expect(url).toContain('search=Microsoft')
    })

    it('omits the search param when not provided', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, page: 1, per_page: 50, data: [] }))
      await fetchVulnerabilities({})
      const [url] = fetchMock.mock.calls[0]
      expect(url).not.toContain('search=')
    })
  })
})
