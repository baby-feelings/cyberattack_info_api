import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fetchCodescanList, fetchCodescanStats } from './codescan'

describe('api/codescan', () => {
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  describe('fetchCodescanList', () => {
    it('includes repo, owner, severity, resolved, min_cvss when provided', async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true, json: () => Promise.resolve({ total: 0, page: 1, per_page: 30, data: [] }),
      })
      await fetchCodescanList({
        repo: 'owner/repo', owner: 'owner', severity: 'ERROR', resolved: false, minCvss: 7,
      })
      const [url] = fetchMock.mock.calls[0]
      expect(url).toContain('repo=owner%2Frepo')
      expect(url).toContain('owner=owner')
      expect(url).toContain('severity=ERROR')
      expect(url).toContain('resolved=false')
      expect(url).toContain('min_cvss=7')
    })

    it('omits optional params when not provided', async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true, json: () => Promise.resolve({ total: 0, page: 1, per_page: 30, data: [] }),
      })
      await fetchCodescanList({})
      const [url] = fetchMock.mock.calls[0]
      expect(url).not.toContain('repo=')
      expect(url).not.toContain('owner=')
      expect(url).not.toContain('severity=')
      expect(url).not.toContain('resolved=')
      expect(url).not.toContain('min_cvss=')
    })

    it('defaults page and per_page', async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true, json: () => Promise.resolve({ total: 0, page: 1, per_page: 30, data: [] }),
      })
      await fetchCodescanList({})
      const [url] = fetchMock.mock.calls[0]
      expect(url).toContain('page=1')
      expect(url).toContain('per_page=30')
    })

    it('sends the session token as Authorization when authToken is given (Issue #219)', async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true, json: () => Promise.resolve({ total: 0, page: 1, per_page: 30, data: [] }),
      })
      await fetchCodescanList({ authToken: 'session-token-abc' })
      const [, opts] = fetchMock.mock.calls[0]
      expect(opts.headers).toEqual({ Authorization: 'Bearer session-token-abc' })
    })
  })

  describe('fetchCodescanStats', () => {
    it('calls the stats endpoint', async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true, json: () => Promise.resolve({ total: 0, repos: [], severities: [] }),
      })
      await fetchCodescanStats()
      const [url] = fetchMock.mock.calls[0]
      expect(url).toContain('/api/codescan/stats')
    })

    it('sends the session token as Authorization when authToken is given (Issue #219)', async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true, json: () => Promise.resolve({ total: 0, repos: [], severities: [] }),
      })
      await fetchCodescanStats('session-token-abc')
      const [, opts] = fetchMock.mock.calls[0]
      expect(opts.headers).toEqual({ Authorization: 'Bearer session-token-abc' })
    })
  })
})
