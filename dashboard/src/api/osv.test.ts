import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fetchOsvList, fetchOsvStats } from './osv'

describe('api/osv', () => {
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  describe('fetchOsvList / fetchOsvStats', () => {
    it('includes ecosystem, severity, sort_by when provided', async () => {
      fetchMock.mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ total: 0, page: 1, per_page: 50, data: [] }) })
      await fetchOsvList({ ecosystem: 'PyPI', severity: 'HIGH', sortBy: 'cvss' })
      const [url] = fetchMock.mock.calls[0]
      expect(url).toContain('ecosystem=PyPI')
      expect(url).toContain('severity=HIGH')
      expect(url).toContain('sort_by=cvss')
      expect(url).toContain('days=180')
    })

    it('omits ecosystem/severity/search/sortBy when not provided', async () => {
      fetchMock.mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ total: 0, page: 1, per_page: 50, data: [] }) })
      await fetchOsvList({})
      const [url] = fetchMock.mock.calls[0]
      expect(url).not.toContain('ecosystem=')
      expect(url).not.toContain('severity=')
      expect(url).not.toContain('search=')
      expect(url).not.toContain('sort_by=')
    })

    it('defaults fetchOsvStats to 180 days', async () => {
      fetchMock.mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ total: 0, ecosystems: [], severities: [], monthly_trend: [] }) })
      await fetchOsvStats()
      const [url] = fetchMock.mock.calls[0]
      expect(url).toContain('days=180')
    })

    it('accepts a custom days value for fetchOsvStats', async () => {
      fetchMock.mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({ total: 0, ecosystems: [], severities: [], monthly_trend: [] }) })
      await fetchOsvStats(30)
      const [url] = fetchMock.mock.calls[0]
      expect(url).toContain('days=30')
    })
  })
})
