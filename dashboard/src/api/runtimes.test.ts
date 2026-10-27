import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fetchRuntimes, fetchRuntimeRepos, fetchRuntimeReleases } from './runtimes'
import { BASE_URL, jsonResponse } from '../test/http'

describe('api/runtimes', () => {
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  describe('fetchRuntimes', () => {
    it('requests the plain endpoint without any query when no condition is given', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, data: [] }))
      await fetchRuntimes({})
      const [url] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/api/runtimes`)
    })

    it('sends the conditions and the session token', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, data: [] }))
      await fetchRuntimes({
        repo: 'baby-feelings/app-one', runtime: 'python', needsAction: true,
        operating: 'active', authToken: 'session-token-abc',
      })
      const [url, opts] = fetchMock.mock.calls[0]
      const parsed = new URL(url)
      expect(parsed.pathname).toBe('/api/runtimes')
      expect(parsed.searchParams.get('repo')).toBe('baby-feelings/app-one')
      expect(parsed.searchParams.get('runtime')).toBe('python')
      expect(parsed.searchParams.get('needs_action')).toBe('true')
      expect(parsed.searchParams.get('operating')).toBe('active')
      expect(opts.headers).toEqual({ Authorization: 'Bearer session-token-abc' })
    })

    it('omits operating=all and an unchecked needs-action filter', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, data: [] }))
      await fetchRuntimes({ operating: 'all', needsAction: false })
      expect(fetchMock.mock.calls[0][0]).toBe(`${BASE_URL}/api/runtimes`)
    })

    it('throws when the request fails', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 500 }))
      await expect(fetchRuntimes({})).rejects.toThrow()
    })
  })

  describe('fetchRuntimeRepos', () => {
    it('passes the operating status and the session token', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ repos: [] }))
      await fetchRuntimeRepos('session-token-abc', 'inactive')
      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/api/runtimes/repos?operating=inactive`)
      expect(opts.headers).toEqual({ Authorization: 'Bearer session-token-abc' })
    })

    it('has no query for all', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ repos: [] }))
      await fetchRuntimeRepos(undefined, 'all')
      expect(fetchMock.mock.calls[0][0]).toBe(`${BASE_URL}/api/runtimes/repos`)
    })
  })

  describe('fetchRuntimeReleases', () => {
    it('requests the releases endpoint', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ data: [] }))
      await fetchRuntimeReleases('session-token-abc')
      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/api/runtimes/releases`)
      expect(opts.headers).toEqual({ Authorization: 'Bearer session-token-abc' })
    })
  })
})
