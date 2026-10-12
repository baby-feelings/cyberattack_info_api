import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { authorizedFetch } from './request'
import { BASE_URL, jsonResponse } from '../../test/http'
import { UnauthorizedError } from '../shared'

describe('authorizedFetch', () => {
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('sends only the Bearer header for a plain GET', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({}))
    await authorizedFetch('/auth/x', 'tok', 'X error')
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe(`${BASE_URL}/auth/x`)
    expect(init).toEqual({ headers: { Authorization: 'Bearer tok' } })
  })

  it('sends a JSON body with Content-Type and the given method', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({}))
    await authorizedFetch('/auth/x', 'tok', 'X error', { method: 'PUT', body: { a: 1 } })
    const [, init] = fetchMock.mock.calls[0]
    expect(init.method).toBe('PUT')
    expect(init.body).toBe('{"a":1}')
    expect(init.headers).toEqual({ Authorization: 'Bearer tok', 'Content-Type': 'application/json' })
  })

  it('throws UnauthorizedError on 401', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 401 }))
    await expect(authorizedFetch('/auth/x', 'tok', 'X error')).rejects.toBeInstanceOf(UnauthorizedError)
  })

  it('throws a fixed message for other failures (does not leak the server detail)', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ detail: 'internal secret' }, { ok: false, status: 500 }))
    await expect(authorizedFetch('/auth/x', 'tok', 'X error')).rejects.toThrow('X error 500')
  })

  it('uses the server detail only for the statuses listed in explain', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ detail: 'limit reached' }, { ok: false, status: 409 }))
    await expect(authorizedFetch('/auth/x', 'tok', 'X error', { explain: [409] })).rejects.toThrow('limit reached')
    fetchMock.mockResolvedValueOnce(jsonResponse({ detail: 'internal' }, { ok: false, status: 500 }))
    await expect(authorizedFetch('/auth/x', 'tok', 'X error', { explain: [409] })).rejects.toThrow('X error 500')
  })

  it("explain: 'any' uses the detail for every failure, falling back to the label", async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ detail: 'bad url' }, { ok: false, status: 400 }))
    await expect(authorizedFetch('/auth/x', 'tok', 'X error', { explain: 'any' })).rejects.toThrow('bad url')
    fetchMock.mockResolvedValueOnce({ ok: false, status: 502, json: () => Promise.reject(new Error('no json')) } as Response)
    await expect(authorizedFetch('/auth/x', 'tok', 'X error', { explain: 'any' })).rejects.toThrow('X error 502')
  })
})
