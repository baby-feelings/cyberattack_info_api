import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { apiFetch, UnauthorizedError } from './shared'
import { fetchDepscanStats } from './depscan'

function jsonResponse(body: unknown, init: { ok?: boolean; status?: number } = {}) {
  return {
    ok: init.ok ?? true,
    status: init.status ?? 200,
    json: () => Promise.resolve(body),
  } as Response
}

describe('api/shared', () => {
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  describe('apiFetch', () => {
    it('sends X-API-KEY when no authToken is given', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ ok: true }))
      await apiFetch('/api/example')
      const [, opts] = fetchMock.mock.calls[0]
      expect(opts.headers).toHaveProperty('X-API-KEY')
    })

    it('throws UnauthorizedError on 401 when an authToken was used', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 401 }))
      await expect(apiFetch('/api/example', 'session-token')).rejects.toBeInstanceOf(UnauthorizedError)
    })

    it('does not throw UnauthorizedError on 401 without an authToken (falls through to generic error)', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 401 }))
      await expect(apiFetch('/api/example')).rejects.not.toBeInstanceOf(UnauthorizedError)
    })

    it('throws a generic Error with the path on non-401 failures', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 500 }))
      await expect(apiFetch('/api/example')).rejects.toThrow('API error 500: /api/example')
    })
  })

  // apiFetch の authToken 分岐（Authorization ヘッダー送信）は、DEPSCAN の
  // fetchDepscanStats 経由で間接的にも検証する（実際のドメイン利用パターン）。
  describe('apiFetch via a domain caller (authToken branch)', () => {
    it('sends Authorization: Bearer when a domain function passes authToken', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ total: 0, repos: [], severities: [] }))
      await fetchDepscanStats('session-token-xyz')
      const [, opts] = fetchMock.mock.calls[0]
      expect(opts.headers).toEqual({ Authorization: 'Bearer session-token-xyz' })
    })
  })
})
