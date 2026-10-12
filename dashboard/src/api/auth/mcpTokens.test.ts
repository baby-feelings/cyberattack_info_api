import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { issueMcpToken, listMcpTokens, revokeMcpToken } from './mcpTokens'
import { BASE_URL, jsonResponse } from '../../test/http'
import { UnauthorizedError } from '../shared'

describe('api/auth/mcpTokens', () => {
  let fetchMock: ReturnType<typeof vi.fn>

  beforeEach(() => {
    fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  describe('issueMcpToken', () => {
    it('POSTs the selected days with the session token and returns the issued token', async () => {
      fetchMock.mockResolvedValueOnce(
        jsonResponse({ token: 'mcp-1', username: 'octocat', id: 't1', expires_at: '2026-10-17T00:00:00+00:00' }),
      )
      const result = await issueMcpToken('tok-123', 7)
      expect(result.token).toBe('mcp-1')
      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/auth/mcp-token`)
      expect(opts.method).toBe('POST')
      expect(opts.headers.Authorization).toBe('Bearer tok-123')
      expect(JSON.parse(opts.body)).toEqual({ days: 7 })
    })

    it('defaults to 30 days', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ token: 'm' }))
      await issueMcpToken('tok')
      expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ days: 30 })
    })

    it('throws UnauthorizedError on 401', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 401 }))
      await expect(issueMcpToken('bad')).rejects.toBeInstanceOf(UnauthorizedError)
    })

    it('passes the server explanation through on 409 (limit reached)', async () => {
      fetchMock.mockResolvedValueOnce(
        jsonResponse({ detail: '上限に達しています' }, { ok: false, status: 409 }),
      )
      await expect(issueMcpToken('tok')).rejects.toThrow('上限に達しています')
    })

    it('falls back to a status message on 409 without a body', async () => {
      fetchMock.mockResolvedValueOnce({
        ok: false, status: 409, json: () => Promise.reject(new Error('no body')),
      } as Response)
      await expect(issueMcpToken('tok')).rejects.toThrow('MCP token error 409')
    })

    it('does not leak server details on other failures', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ detail: 'boom' }, { ok: false, status: 500 }))
      await expect(issueMcpToken('tok')).rejects.toThrow('MCP token error 500')
    })
  })

  describe('listMcpTokens', () => {
    it('GETs the token list with the session token', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ tokens: [{ id: 't1', status: 'active' }] }))
      const result = await listMcpTokens('tok-123')
      expect(result).toEqual([{ id: 't1', status: 'active' }])
      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/auth/mcp-tokens`)
      expect(opts.headers.Authorization).toBe('Bearer tok-123')
    })

    it('throws UnauthorizedError on 401 and a generic error otherwise', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 401 }))
      await expect(listMcpTokens('bad')).rejects.toBeInstanceOf(UnauthorizedError)
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 500 }))
      await expect(listMcpTokens('tok')).rejects.toThrow('MCP token list error 500')
    })
  })

  describe('revokeMcpToken', () => {
    it('DELETEs the token by id with the session token', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({ id: 't 1', revoked: true }))
      await revokeMcpToken('tok-123', 't 1')
      const [url, opts] = fetchMock.mock.calls[0]
      expect(url).toBe(`${BASE_URL}/auth/mcp-tokens/t%201`)
      expect(opts.method).toBe('DELETE')
      expect(opts.headers.Authorization).toBe('Bearer tok-123')
    })

    it('throws UnauthorizedError on 401 and a generic error otherwise', async () => {
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 401 }))
      await expect(revokeMcpToken('bad', 't1')).rejects.toBeInstanceOf(UnauthorizedError)
      fetchMock.mockResolvedValueOnce(jsonResponse({}, { ok: false, status: 404 }))
      await expect(revokeMcpToken('tok', 't1')).rejects.toThrow('MCP token revoke error 404')
    })
  })

})
