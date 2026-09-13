import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { githubLoginUrl, fetchScanStatus, exchangeAuthCode } from './auth'
import { UnauthorizedError } from './shared'

const BASE_URL = 'https://cyberattack-info-api.onrender.com'

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    json: () => Promise.resolve(body),
  } as Response
}

describe('api/auth', () => {
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  describe('githubLoginUrl', () => {
    it('points at the backend /auth/github/login endpoint', () => {
      expect(githubLoginUrl()).toBe(`${BASE_URL}/auth/github/login`)
    })
  })

  describe('fetchScanStatus', () => {
    it('sends the Bearer token and returns the parsed status', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ username: 'octocat', status: 'done' }))
      const result = await fetchScanStatus('tok-123')
      expect(result.status).toBe('done')
      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/auth/scan-status`)
      expect(opts.headers).toEqual({ Authorization: 'Bearer tok-123' })
    })

    it('throws UnauthorizedError specifically on 401', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 401 }))
      await expect(fetchScanStatus('bad-token')).rejects.toBeInstanceOf(UnauthorizedError)
    })

    it('throws a generic Error on other failures (not UnauthorizedError)', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 500 }))
      await expect(fetchScanStatus('tok')).rejects.toThrow('Scan status error 500')
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 500 }))
      await expect(fetchScanStatus('tok')).rejects.not.toBeInstanceOf(UnauthorizedError)
    })
  })

  describe('exchangeAuthCode', () => {
    it('POSTs the code as JSON and returns the token/username', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ token: 'tok-abc', username: 'octocat' }))
      const result = await exchangeAuthCode('code-123')
      expect(result).toEqual({ token: 'tok-abc', username: 'octocat' })
      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/auth/exchange`)
      expect(opts.method).toBe('POST')
      expect(JSON.parse(opts.body)).toEqual({ code: 'code-123' })
    })

    it('throws when the code is invalid, expired, or already used', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 400 }))
      await expect(exchangeAuthCode('bad-code')).rejects.toThrow('Exchange error 400')
    })
  })
})
