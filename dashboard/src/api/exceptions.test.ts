import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { createException, revokeException, EXCEPTION_STATUS_LABELS } from './exceptions'
import { BASE_URL, jsonResponse } from '../test/http'
import { UnauthorizedError } from './shared'

const INPUT = {
  kind: 'dependency' as const,
  repo_full_name: 'alice/api',
  finding_key: 'npm|lodash|GHSA-1',
  status: 'accepted' as const,
  reason: '修正版が無い',
  expires_at: '2026-12-31T23:59:59Z',
}

describe('api/exceptions', () => {
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('has a Japanese label for every status', () => {
    expect(EXCEPTION_STATUS_LABELS).toEqual({
      accepted: '受容', false_positive: '誤検知', not_affected: '影響なし',
    })
  })

  describe('createException', () => {
    it('POSTs the exception as JSON with the Bearer token', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ id: 1 }, { status: 201 }))

      await createException('tok-1', INPUT)

      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/api/exceptions`)
      expect(opts.method).toBe('POST')
      expect(opts.headers.Authorization).toBe('Bearer tok-1')
      expect(JSON.parse(opts.body)).toEqual(INPUT)
    })

    it('shows the server explanation for input mistakes (422)', async () => {
      fetchMock.mockResolvedValueOnce(
        jsonResponse({ detail: '受容には、期限が必要です。' }, { ok: false, status: 422 }),
      )
      await expect(createException('tok-1', INPUT)).rejects.toThrow('受容には、期限が必要です。')
    })

    it('shows the server explanation when the finding is missing (404) or not owned (403)', async () => {
      fetchMock.mockResolvedValueOnce(
        jsonResponse({ detail: '対象の検知が見つかりません。' }, { ok: false, status: 404 }),
      )
      await expect(createException('t', INPUT)).rejects.toThrow('対象の検知が見つかりません。')

      fetchMock.mockResolvedValueOnce(jsonResponse({ detail: 'no' }, { ok: false, status: 403 }))
      await expect(createException('t', INPUT)).rejects.toThrow('no')
    })

    it('hides internal details of other failures', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ detail: 'secret' }, { ok: false, status: 500 }))
      await expect(createException('t', INPUT)).rejects.toThrow('Exception error 500')
    })

    it('throws UnauthorizedError on 401', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 401 }))
      await expect(createException('bad', INPUT)).rejects.toBeInstanceOf(UnauthorizedError)
    })
  })

  describe('revokeException', () => {
    it('DELETEs the exception by id', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ id: 7 }))

      await revokeException('tok-1', 7)

      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/api/exceptions/7`)
      expect(opts.method).toBe('DELETE')
    })

    it('reports a conflict (already ended) generically', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 409 }))
      await expect(revokeException('t', 7)).rejects.toThrow('Exception error 409')
    })
  })
})
