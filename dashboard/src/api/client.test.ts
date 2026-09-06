import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  fetchHealth, fetchRecent, fetchStats, fetchVulnerabilities,
  fetchOsvList, fetchOsvStats, fetchJvnList, fetchJvnStats,
  fetchDepscanList, fetchDepscanStats, fetchAllDepscanFindings,
  fetchCrawlerLogs, githubLoginUrl, fetchScanStatus, logout, UnauthorizedError,
  type DepscanListResponse,
} from './client'

const BASE_URL = 'https://cyberattack-info-api.onrender.com'

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    json: () => Promise.resolve(body),
  } as Response
}

describe('api/client', () => {
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

  describe('fetchOsvList / fetchOsvStats', () => {
    it('includes ecosystem, severity, sort_by when provided', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, page: 1, per_page: 50, data: [] }))
      await fetchOsvList({ ecosystem: 'PyPI', severity: 'HIGH', sortBy: 'cvss' })
      const [url] = fetchMock.mock.calls[0]
      expect(url).toContain('ecosystem=PyPI')
      expect(url).toContain('severity=HIGH')
      expect(url).toContain('sort_by=cvss')
      expect(url).toContain('days=180')
    })

    it('defaults fetchOsvStats to 180 days', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, ecosystems: [], severities: [], monthly_trend: [] }))
      await fetchOsvStats()
      const [url] = fetchMock.mock.calls[0]
      expect(url).toContain('days=180')
    })
  })

  describe('fetchJvnList / fetchJvnStats', () => {
    it('includes severity and search when provided', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, page: 1, per_page: 50, data: [] }))
      await fetchJvnList({ severity: 'High', search: 'Apache' })
      const [url] = fetchMock.mock.calls[0]
      expect(url).toContain('severity=High')
      expect(url).toContain('search=Apache')
    })

    it('requests /api/jvn/stats with the given days', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, severities: [], monthly_trend: [] }))
      await fetchJvnStats(30)
      const [url] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/api/jvn/stats?days=30`)
    })
  })

  describe('fetchDepscanList', () => {
    it('sends the request with credentials included (HttpOnly session cookie), no headers', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, page: 1, per_page: 50, data: [] }))
      await fetchDepscanList({})
      const [, opts] = fetchMock.mock.calls[0]
      expect(opts.credentials).toBe('include')
      expect(opts.headers).toEqual({})
    })

    it('omits owner/severity/resolved when not set', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, page: 1, per_page: 50, data: [] }))
      await fetchDepscanList({})
      const [url] = fetchMock.mock.calls[0]
      expect(url).not.toContain('owner=')
      expect(url).not.toContain('severity=')
      expect(url).not.toContain('resolved=')
    })

    it('includes resolved=false explicitly (not omitted like null)', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, page: 1, per_page: 50, data: [] }))
      await fetchDepscanList({ resolved: false })
      const [url] = fetchMock.mock.calls[0]
      expect(url).toContain('resolved=false')
    })
  })

  describe('fetchDepscanStats', () => {
    it('sends the request with credentials included (HttpOnly session cookie)', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, repos: [], severities: [] }))
      await fetchDepscanStats()
      const [, opts] = fetchMock.mock.calls[0]
      expect(opts.credentials).toBe('include')
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
  })

  describe('githubLoginUrl', () => {
    it('points at the backend /auth/github/login endpoint', () => {
      expect(githubLoginUrl()).toBe(`${BASE_URL}/auth/github/login`)
    })
  })

  describe('fetchScanStatus', () => {
    it('sends the request with credentials included and returns the parsed status', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ username: 'octocat', status: 'done' }))
      const result = await fetchScanStatus()
      expect(result.status).toBe('done')
      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/auth/scan-status`)
      expect(opts.credentials).toBe('include')
    })

    it('throws UnauthorizedError specifically on 401', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 401 }))
      await expect(fetchScanStatus()).rejects.toBeInstanceOf(UnauthorizedError)
    })

    it('throws a generic Error on other failures (not UnauthorizedError)', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 500 }))
      await expect(fetchScanStatus()).rejects.toThrow('Scan status error 500')
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 500 }))
      await expect(fetchScanStatus()).rejects.not.toBeInstanceOf(UnauthorizedError)
    })
  })

  describe('logout', () => {
    it('POSTs to /auth/logout with credentials included', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ logged_out: true }))
      await logout()
      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/auth/logout`)
      expect(opts.method).toBe('POST')
      expect(opts.credentials).toBe('include')
    })
  })
})
